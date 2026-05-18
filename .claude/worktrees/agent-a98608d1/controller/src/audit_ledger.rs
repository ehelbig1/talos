use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::Result;
use async_nats::jetstream::{self, stream::Config as StreamConfig, Message};
use async_nats::Client;
use aws_config::BehaviorVersion;
use aws_sdk_s3::{primitives::ByteStream, Client as S3Client};
use chrono::Utc;
use futures_util::stream::StreamExt;
use serde_json::Value;
use sqlx::PgPool;
use std::collections::HashMap;
use std::time::Duration;
use uuid::Uuid;

use lru::LruCache;
use opentelemetry::{
    trace::{Span, Status, Tracer, TracerProvider as _},
    KeyValue,
};
use opentelemetry_otlp::{WithExportConfig, WithTonicConfig};
use opentelemetry_sdk::{trace::TracerProvider, Resource};
use std::num::NonZeroUsize;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Cache of OTLP Exporters per Tenant
struct OTLPCache {
    providers: Mutex<LruCache<Uuid, TracerProvider>>,
}

impl OTLPCache {
    fn new() -> Self {
        Self {
            providers: Mutex::new(LruCache::new(
                NonZeroUsize::new(100).unwrap_or_else(|| unsafe { NonZeroUsize::new_unchecked(1) }),
            )),
        }
    }

    async fn get_tracer(
        &self,
        user_id: Uuid,
        pool: &PgPool,
    ) -> Option<opentelemetry_sdk::trace::Tracer> {
        // Check cache first
        {
            let mut providers = self.providers.lock().await;
            if let Some(provider) = providers.get(&user_id) {
                return Some(provider.clone().tracer("talos-audit-exporter"));
            }
        }

        // Fetch settings from DB
        #[derive(sqlx::FromRow)]
        struct SettingsRow {
            streaming_enabled: bool,
            otlp_endpoint: Option<String>,
            otlp_protocol: Option<String>,
            auth_headers_encrypted: Option<Vec<u8>>,
            auth_headers_nonce: Option<Vec<u8>>,
        }
        let settings = sqlx::query_as::<_, SettingsRow>(
            r#"
            SELECT streaming_enabled, otlp_endpoint, otlp_protocol, auth_headers_encrypted, auth_headers_nonce
            FROM user_audit_settings
            WHERE user_id = $1
            "#
        ).bind(user_id).fetch_optional(pool).await.ok()??;

        if !settings.streaming_enabled {
            return None;
        }

        let endpoint = settings.otlp_endpoint?;

        let mut metadata = tonic::metadata::MetadataMap::new();

        if let (Some(encrypted), Some(nonce)) =
            (settings.auth_headers_encrypted, settings.auth_headers_nonce)
        {
            if let Ok(master_key_hex) = std::env::var("TALOS_MASTER_KEY") {
                if let Ok(master_key) = hex::decode(master_key_hex.trim()) {
                    if let Ok(cipher) = Aes256Gcm::new_from_slice(&master_key) {
                        let nonce_obj = Nonce::from_slice(&nonce);
                        if let Ok(plaintext) = cipher.decrypt(nonce_obj, encrypted.as_ref()) {
                            if let Ok(json_headers) =
                                serde_json::from_slice::<HashMap<String, String>>(&plaintext)
                            {
                                for (k, v) in json_headers {
                                    if let (Ok(key), Ok(val)) = (k.parse::<tonic::metadata::MetadataKey<tonic::metadata::Ascii>>(), v.parse::<tonic::metadata::MetadataValue<tonic::metadata::Ascii>>()) {
                                        metadata.insert(key, val);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .with_metadata(metadata)
            .build()
            .ok()?;

        let provider = TracerProvider::builder()
            .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
            .with_resource(Resource::new(vec![
                KeyValue::new("service.name", "talos-audit-stream"),
                KeyValue::new("tenant.id", user_id.to_string()),
            ]))
            .build();

        let tracer = provider.tracer("talos-audit-exporter");

        let mut providers = self.providers.lock().await;
        providers.put(user_id, provider);

        Some(tracer)
    }
}

pub async fn start_audit_ledger_subscriber(nc: Client, db_pool: PgPool) -> Result<()> {
    tracing::info!("Initializing audit ledger subscriber");
    tracing::debug!("Audit ledger subscriber initialisation proceeding");

    let js = jetstream::new(nc);

    // Ensure the stream exists for guaranteed delivery
    let stream_name = "AUDIT_LEDGER";
    let subject = "talos.audit.ledger";
    let _stream = js
        .get_or_create_stream(StreamConfig {
            name: stream_name.to_string(),
            subjects: vec![subject.to_string()],
            ..Default::default()
        })
        .await?;

    // Create a pull consumer
    let consumer = _stream
        .get_or_create_consumer(
            "audit_ledger_processor",
            async_nats::jetstream::consumer::pull::Config {
                durable_name: Some("audit_ledger_processor".to_string()),
                ..Default::default()
            },
        )
        .await?;

    let mut messages = consumer.messages().await?;

    // Initialise optional S3 client
    let s3_client: Option<S3Client> =
        if std::env::var("AWS_ENDPOINT_URL").is_ok() || std::env::var("MINIO_ENDPOINT").is_ok() {
            if std::env::var("AWS_ENDPOINT_URL").is_err() {
                std::env::set_var(
                    "AWS_ENDPOINT_URL",
                    std::env::var("MINIO_ENDPOINT")
                        .map_err(|_| anyhow::anyhow!("MINIO_ENDPOINT env var not set"))?,
                );
            }
            let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
            let mut builder = aws_sdk_s3::config::Builder::from(&config);
            if std::env::var("AWS_S3_FORCE_PATH_STYLE").unwrap_or_default() == "true" {
                builder = builder.force_path_style(true);
            }
            Some(S3Client::from_conf(builder.build()))
        } else {
            None
        };

    tracing::info!(
        "Audit ledger subscriber ready – S3 client {}",
        if s3_client.is_some() {
            "configured"
        } else {
            "not configured"
        }
    );

    tokio::spawn(async move {
        tracing::info!("🔒 Started WORM Cryptographic Ledger subscriber on 'talos.audit.ledger'");
        let otlp_cache = Arc::new(OTLPCache::new());
        println!("🔒 Started WORM Cryptographic Ledger subscriber on 'talos.audit.ledger'");

        let bucket = std::env::var("MINIO_BUCKET").unwrap_or_else(|_| "audit-logs".to_string());
        let mut batch: Vec<Message> = Vec::new();
        let max_batch_size = 100;
        let mut interval = tokio::time::interval(Duration::from_secs(5));

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if !batch.is_empty() {
                        process_batch(&mut batch, &s3_client, &bucket, &db_pool, &otlp_cache).await;
                    }
                }
                msg_result = messages.next() => {
                    match msg_result {
                        Some(Ok(msg)) => {
                            batch.push(msg);
                            if batch.len() >= max_batch_size {
                                process_batch(&mut batch, &s3_client, &bucket, &db_pool, &otlp_cache).await;
                                interval.reset();
                            }
                        }
                        Some(Err(e)) => {
                            tracing::error!("Error receiving message from JetStream: {}", e);
                        }
                        None => {
                            tracing::warn!("Audit ledger JetStream consumer ended unexpectedly");
                            break;
                        }
                    }
                }
            }
        }
    });

    Ok(())
}

async fn process_batch(
    batch: &mut Vec<Message>,
    s3_client: &Option<S3Client>,
    bucket: &str,
    db_pool: &PgPool,
    otlp_cache: &Arc<OTLPCache>,
) {
    if batch.is_empty() {
        return;
    }

    tracing::debug!("Processing WORM batch of {} audit messages", batch.len());

    let mut invalid_messages = Vec::new();
    let mut grouped_messages: HashMap<String, Vec<(Value, usize)>> = HashMap::new();

    for (idx, msg) in batch.iter().enumerate() {
        if let Ok(wrapper) = serde_json::from_slice::<Value>(&msg.payload) {
            if let Some(event) = wrapper.get("event") {
                let execution_id = event["execution_id"]
                    .as_str()
                    .unwrap_or("unknown")
                    .to_string();
                let workflow_id = event["workflow_id"]
                    .as_str()
                    .unwrap_or("unknown")
                    .to_string();

                // Fetch User ID
                let mut user_id_opt = None;
                if let Ok(wid) = Uuid::parse_str(&workflow_id) {
                    if let Ok(Some(uid)) = sqlx::query_scalar::<_, Uuid>(
                        "SELECT user_id FROM workflow_executions WHERE id = $1",
                    )
                    .bind(wid)
                    .fetch_optional(db_pool)
                    .await
                    {
                        user_id_opt = Some(uid);
                    } else if let Ok(Some(uid)) = sqlx::query_scalar::<_, Uuid>(
                        "SELECT user_id FROM module_executions WHERE id = $1",
                    )
                    .bind(wid)
                    .fetch_optional(db_pool)
                    .await
                    {
                        user_id_opt = Some(uid);
                    }
                }

                // OTLP Streaming (The BYOD Feature)
                if let Some(user_id) = user_id_opt {
                    if let Some(tracer) = otlp_cache.get_tracer(user_id, db_pool).await {
                        let mut span = tracer.start("audit_event");
                        span.set_attribute(KeyValue::new("talos.workflow.id", workflow_id.clone()));
                        span.set_attribute(KeyValue::new(
                            "talos.execution.id",
                            execution_id.clone(),
                        ));
                        span.set_attribute(KeyValue::new(
                            "talos.crypto.sequence",
                            event["sequence_num"].as_u64().unwrap_or(0) as i64,
                        ));
                        span.set_attribute(KeyValue::new(
                            "talos.actor",
                            event["actor"].as_str().unwrap_or("unknown").to_string(),
                        ));
                        span.set_attribute(KeyValue::new(
                            "talos.action",
                            event["action"].as_str().unwrap_or("unknown").to_string(),
                        ));
                        if let Some(hash) = wrapper.get("hash").and_then(|h| h.as_str()) {
                            span.set_attribute(KeyValue::new(
                                "talos.crypto.hash",
                                hash.to_string(),
                            ));
                        }
                        if let Some(prev) = event.get("previous_hash").and_then(|h| h.as_str()) {
                            span.set_attribute(KeyValue::new(
                                "talos.crypto.previous_hash",
                                prev.to_string(),
                            ));
                        }
                        span.set_attribute(KeyValue::new(
                            "talos.payload",
                            event["payload"].as_str().unwrap_or("").to_string(),
                        ));
                        span.set_status(Status::Ok);
                        span.end();
                    }
                }

                let hash = wrapper
                    .get("hash")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                tracing::info!(
                    "WORM_LEDGER_APPEND [{}] Seq: {} | Actor: {} | Action: {} | Hash: {}",
                    execution_id,
                    event["sequence_num"].as_u64().unwrap_or(0),
                    event["actor"].as_str().unwrap_or("unknown"),
                    event["action"].as_str().unwrap_or("unknown"),
                    hash
                );

                grouped_messages
                    .entry(execution_id)
                    .or_default()
                    .push((wrapper, idx));
            } else {
                tracing::warn!(
                    "Audit message missing 'event' object. Payload: {:?}",
                    wrapper
                );
                invalid_messages.push(idx);
            }
        } else {
            tracing::warn!("Received unparseable audit ledger message. Dropping poison pill.");
            invalid_messages.push(idx);
        }
    }

    let mut successful_indices = Vec::new();
    let mut failed_indices = Vec::new();

    if let Some(client) = s3_client {
        for (execution_id, items) in grouped_messages {
            let mut payload_bytes = Vec::new();
            let mut min_seq = u64::MAX;
            let mut max_seq = 0;
            let mut current_indices = Vec::new();

            for (wrapper, idx) in items {
                let seq = wrapper
                    .get("event")
                    .and_then(|e| e.get("sequence_num"))
                    .and_then(|s| s.as_u64())
                    .unwrap_or(0);
                if seq < min_seq {
                    min_seq = seq;
                }
                if seq > max_seq {
                    max_seq = seq;
                }

                if let Ok(mut bytes) = serde_json::to_vec(&wrapper) {
                    bytes.push(b'\n'); // JSON-Lines format
                    payload_bytes.extend(bytes);
                    current_indices.push(idx);
                }
            }

            if min_seq > max_seq {
                min_seq = 0;
            }

            let key = format!(
                "{}/{}_{}_{}.jsonl",
                execution_id,
                min_seq,
                max_seq,
                Utc::now()
                    .timestamp_nanos_opt()
                    .unwrap_or_else(|| Utc::now().timestamp())
            );

            match client
                .put_object()
                .bucket(bucket)
                .key(&key)
                .body(ByteStream::from(payload_bytes))
                .send()
                .await
            {
                Ok(_) => {
                    tracing::debug!(
                        "Persisted batched audit events to bucket {} with key {}",
                        bucket,
                        key
                    );
                    successful_indices.extend(current_indices);
                }
                Err(e) => {
                    tracing::error!("Failed to persist batched audit events to {}: {}", key, e);
                    failed_indices.extend(current_indices);
                }
            }
        }
    } else {
        // If S3 is not configured, we consider all parsed messages successful
        for (_, items) in grouped_messages {
            for (_, idx) in items {
                successful_indices.push(idx);
            }
        }
    }

    // Acknowledge all processed messages (valid and successfully persisted, plus invalid ones so they don't block)
    let mut all_to_ack = invalid_messages;
    all_to_ack.extend(successful_indices);

    for idx in all_to_ack {
        if let Some(msg) = batch.get(idx) {
            if let Err(e) = msg.ack().await {
                tracing::error!("Failed to acknowledge NATS message: {}", e);
            }
        }
    }

    if !failed_indices.is_empty() {
        tracing::warn!(
            "{} messages failed to process and were not acknowledged, will be redelivered",
            failed_indices.len()
        );
    }

    // Clear the batch so we start fresh. Failed messages remain unacknowledged
    // and JetStream will automatically redeliver them after the ack_wait timeout.
    batch.clear();
}
