//! `talos:core/model` — platform ML-model inference (RFC 0011 P2c).
//!
//! The datasets + model registry live behind the controller's Postgres
//! (workers are credential-free), so both methods sign an
//! `MlPredictRequest` over NATS (`talos.ml.predict`) and await the
//! controller subscriber's reply within the protocol timeout. Identity
//! comes exclusively from the job: `actor_id` keys the HMAC, the
//! execution's `user_id` (nil-guarded) scopes model resolution
//! controller-side under RLS — neither is guest-suppliable, per the
//! platform-primitive checklist §4.

use super::*;

impl TalosContext {
    /// Shared kernel for `predict` / `predict-batch`: gates (cancel,
    /// capability world, per-execution input budget, identity), then one
    /// signed request/reply round-trip.
    async fn model_predict_rpc(
        &mut self,
        model_name: String,
        inputs: Vec<String>,
        method: &'static str,
    ) -> Result<wit_model::PredictReply, wit_model::Error> {
        if self.is_cancelled() {
            // Distinct, non-retryable variant + the cancel metric —
            // same convention as `wit_llm::complete` (Timeout invites
            // retry loops against a cancelled execution).
            tracing::info!(module_id = ?self.module_id, "Execution cancelled");
            if let Some(ref m) = self.metrics {
                m.record_execution_cancelled();
            }
            return Err(wit_model::Error::Cancelled);
        }
        // Same capability tier as `wit_embedding::generate` — the model
        // interface ships in the secrets-node+ worlds (grep `import
        // model;` in wit/talos.wit) and the runtime gate must match the
        // WIT linkage (MCP-604/608 class: a mis-tagged module with the
        // import satisfied must still be refused here).
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Secrets
                | CapabilityWorld::Database
                | CapabilityWorld::Agent
                | CapabilityWorld::Trusted
        ) {
            self.record_capability_denied(method, "capability-world", &model_name)
                .await;
            return Err(wit_model::Error::NotAvailable);
        }

        let __start = std::time::Instant::now();
        let __metrics = self.metrics.clone();
        let __res: Result<wit_model::PredictReply, wit_model::Error> = async {
            use talos_memory::ml_rpc::{
                validate_structure, MlPredictRequest, MlPredictResponse, MlRpcError,
                REQUEST_TIMEOUT_MS, SUBJECT_ML_PREDICT,
            };

            // Cheap structural gate before spending the budget counter
            // or a signature. Caps mirror the protocol constants.
            if !validate_structure(&model_name, &inputs) {
                return Err(wit_model::Error::InvalidInput);
            }

            let Some(actor_id) = self.actor_id else {
                // No actor binding — no HMAC identity to sign under.
                return Err(wit_model::Error::NotAvailable);
            };
            let Some(user_id) = self.user_id else {
                // System executions have no tenancy principal to
                // resolve models under; fail closed rather than
                // guessing a scope.
                return Err(wit_model::Error::InvalidInput);
            };
            let Some(nats) = self.nats_client.as_ref().cloned() else {
                return Err(wit_model::Error::NotAvailable);
            };

            // Per-execution input budget, charged only once every
            // prerequisite short of the send is satisfied — a guest
            // retry loop against transient infra (NATS down, missing
            // key) must not burn the budget on requests that never
            // reached the controller. fetch_add is race-free under
            // guest-visible concurrency; overshoot by one batch at the
            // boundary is acceptable — the cap is load-shaping, not a
            // security boundary.
            let batch = inputs.len() as u64;
            let prior = self
                .model_predict_input_count
                .fetch_add(batch, std::sync::atomic::Ordering::Relaxed);
            if prior + batch > crate::host::limits::MAX_MODEL_PREDICT_INPUTS_PER_EXECUTION {
                tracing::warn!(
                    execution_id = ?self.execution_id,
                    used = prior,
                    "model::predict per-execution input budget exhausted"
                );
                return Err(wit_model::Error::RateLimited);
            }

            let req = match MlPredictRequest::new_signed(actor_id, user_id, model_name, inputs) {
                Some(r) => r,
                // HMAC key unavailable — fail closed rather than send
                // an unsigned request.
                None => return Err(wit_model::Error::NotAvailable),
            };
            let payload = match serde_json::to_vec(&req) {
                Ok(p) => p,
                Err(_) => return Err(wit_model::Error::Internal),
            };

            let fut = nats.request(SUBJECT_ML_PREDICT, payload.into());
            let reply_msg = match tokio::time::timeout(
                std::time::Duration::from_millis(REQUEST_TIMEOUT_MS),
                fut,
            )
            .await
            {
                Ok(Ok(m)) => m,
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, "model-predict NATS request failed");
                    return Err(wit_model::Error::NotAvailable);
                }
                Err(_) => return Err(wit_model::Error::Timeout),
            };

            let resp: MlPredictResponse = match serde_json::from_slice(&reply_msg.payload) {
                Ok(r) => r,
                Err(_) => return Err(wit_model::Error::Internal),
            };
            match resp {
                MlPredictResponse::Ok(reply) => Ok(wit_model::PredictReply {
                    predictions: reply
                        .predictions
                        .into_iter()
                        .map(|p| {
                            p.map(|p| wit_model::Prediction {
                                label: p.label,
                                confidence: p.confidence,
                            })
                        })
                        .collect(),
                    model_version: reply.model_version,
                    backend: reply.backend,
                }),
                MlPredictResponse::Err(MlRpcError::NotFound) => Err(wit_model::Error::NotFound),
                MlPredictResponse::Err(MlRpcError::NotPromoted) => {
                    Err(wit_model::Error::NotPromoted)
                }
                MlPredictResponse::Err(MlRpcError::NotAvailable) => {
                    Err(wit_model::Error::NotAvailable)
                }
                MlPredictResponse::Err(MlRpcError::Invalid) => Err(wit_model::Error::InvalidInput),
                MlPredictResponse::Err(MlRpcError::Timeout) => Err(wit_model::Error::Timeout),
                // Unauthorized here means the worker's signature was
                // rejected (key rotation window, clock skew) — an
                // infrastructure condition from the guest's view.
                MlPredictResponse::Err(MlRpcError::Unauthorized)
                | MlPredictResponse::Err(MlRpcError::Internal) => Err(wit_model::Error::Internal),
            }
        }
        .await;
        if let Some(ref m) = __metrics {
            m.record_host_function_call(method, __start.elapsed().as_millis() as f64);
        }
        __res
    }

    /// Kernel for `few-shot`: same gate order as predict (cancel,
    /// capability world, per-execution call budget, identity), one signed
    /// request/reply on `talos.ml.fewshot`.
    async fn model_fewshot_rpc(
        &mut self,
        model_name: String,
        k: u32,
        method: &'static str,
    ) -> Result<Vec<wit_model::FewShotExample>, wit_model::Error> {
        if self.is_cancelled() {
            tracing::info!(module_id = ?self.module_id, "Execution cancelled");
            if let Some(ref m) = self.metrics {
                m.record_execution_cancelled();
            }
            return Err(wit_model::Error::Cancelled);
        }
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Secrets
                | CapabilityWorld::Database
                | CapabilityWorld::Agent
                | CapabilityWorld::Trusted
        ) {
            self.record_capability_denied(method, "capability-world", &model_name)
                .await;
            return Err(wit_model::Error::NotAvailable);
        }

        let __start = std::time::Instant::now();
        let __metrics = self.metrics.clone();
        let __res: Result<Vec<wit_model::FewShotExample>, wit_model::Error> = async {
            use talos_memory::ml_rpc::{
                validate_fewshot_structure, MlFewShotRequest, MlFewShotResponse, MlRpcError,
                REQUEST_TIMEOUT_MS, SUBJECT_ML_FEWSHOT,
            };

            if !validate_fewshot_structure(&model_name, k) {
                return Err(wit_model::Error::InvalidInput);
            }

            let Some(actor_id) = self.actor_id else {
                return Err(wit_model::Error::NotAvailable);
            };
            let Some(user_id) = self.user_id else {
                return Err(wit_model::Error::InvalidInput);
            };
            let Some(nats) = self.nats_client.as_ref().cloned() else {
                return Err(wit_model::Error::NotAvailable);
            };

            // Per-execution CALL budget (few-shot is a per-fallback-leg
            // fetch, not per-item — a handful covers any sane workflow;
            // a guest loop must not turn the decrypt path into a scan).
            let prior = self
                .model_fewshot_call_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if prior + 1 > crate::host::limits::MAX_MODEL_FEWSHOT_CALLS_PER_EXECUTION {
                tracing::warn!(
                    execution_id = ?self.execution_id,
                    used = prior,
                    "model::few-shot per-execution call budget exhausted"
                );
                return Err(wit_model::Error::RateLimited);
            }

            let req = match MlFewShotRequest::new_signed(actor_id, user_id, model_name, k) {
                Some(r) => r,
                None => return Err(wit_model::Error::NotAvailable),
            };
            let payload = match serde_json::to_vec(&req) {
                Ok(p) => p,
                Err(_) => return Err(wit_model::Error::Internal),
            };

            let fut = nats.request(SUBJECT_ML_FEWSHOT, payload.into());
            let reply_msg = match tokio::time::timeout(
                std::time::Duration::from_millis(REQUEST_TIMEOUT_MS),
                fut,
            )
            .await
            {
                Ok(Ok(m)) => m,
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, "model-fewshot NATS request failed");
                    return Err(wit_model::Error::NotAvailable);
                }
                Err(_) => return Err(wit_model::Error::Timeout),
            };

            let resp: MlFewShotResponse = match serde_json::from_slice(&reply_msg.payload) {
                Ok(r) => r,
                Err(_) => return Err(wit_model::Error::Internal),
            };
            match resp {
                MlFewShotResponse::Ok(reply) => Ok(reply
                    .examples
                    .into_iter()
                    .map(|e| wit_model::FewShotExample {
                        features_text: e.features_text,
                        label: e.label,
                    })
                    .collect()),
                MlFewShotResponse::Err(MlRpcError::NotFound) => Err(wit_model::Error::NotFound),
                MlFewShotResponse::Err(MlRpcError::NotPromoted) => {
                    Err(wit_model::Error::NotPromoted)
                }
                MlFewShotResponse::Err(MlRpcError::NotAvailable) => {
                    Err(wit_model::Error::NotAvailable)
                }
                MlFewShotResponse::Err(MlRpcError::Invalid) => Err(wit_model::Error::InvalidInput),
                MlFewShotResponse::Err(MlRpcError::Timeout) => Err(wit_model::Error::Timeout),
                MlFewShotResponse::Err(MlRpcError::Unauthorized)
                | MlFewShotResponse::Err(MlRpcError::Internal) => Err(wit_model::Error::Internal),
            }
        }
        .await;
        if let Some(ref m) = __metrics {
            m.record_host_function_call(method, __start.elapsed().as_millis() as f64);
        }
        __res
    }
}

impl wit_model::Host for TalosContext {
    #[::tracing::instrument(name = "model.predict", skip_all)]
    async fn predict(
        &mut self,
        model_name: String,
        input: String,
    ) -> Result<Option<wit_model::Prediction>, wit_model::Error> {
        let reply = self
            .model_predict_rpc(model_name, vec![input], "model::predict")
            .await?;
        // Exactly one slot by construction; a malformed reply shape is
        // a controller bug — surface it as Internal, not a panic.
        match reply.predictions.into_iter().next() {
            Some(slot) => Ok(slot),
            None => Err(wit_model::Error::Internal),
        }
    }

    #[::tracing::instrument(name = "model.predict_batch", skip_all, fields(inputs = inputs.len()))]
    async fn predict_batch(
        &mut self,
        model_name: String,
        inputs: Vec<String>,
    ) -> Result<wit_model::PredictReply, wit_model::Error> {
        self.model_predict_rpc(model_name, inputs, "model::predict_batch")
            .await
    }

    #[::tracing::instrument(name = "model.few_shot", skip_all, fields(k = k))]
    async fn few_shot(
        &mut self,
        model_name: String,
        k: u32,
    ) -> Result<Vec<wit_model::FewShotExample>, wit_model::Error> {
        self.model_fewshot_rpc(model_name, k, "model::few_shot")
            .await
    }
}
