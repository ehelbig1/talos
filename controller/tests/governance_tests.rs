use crate::common::{create_test_user, setup_test_context, AuthenticatedClient};
use serde_json::json;
use uuid::Uuid;

mod common;

#[ignore = "references dropped wasm_modules/node_templates tables — port fixtures to unified `modules` table (Phase 5)"]
#[tokio::test]
async fn test_dead_letter_queue_flow() {
    let ctx = setup_test_context().await;
    let user_id: Uuid = create_test_user(&ctx.auth_service, "governance@example.com").await;
    let client = AuthenticatedClient::new(user_id, None, vec![], ctx.schema.clone());

    // 1. Seed a workflow node failure into DLQ
    let workflow_id = Uuid::new_v4();
    let execution_id = Uuid::new_v4();
    let node_id = Uuid::new_v4(); // node_id is UUID in dead_letter_queue
    let graph_json = "{}".to_string(); // graph_json is TEXT in workflows

    sqlx::query("INSERT INTO workflows (id, user_id, name, module_uri, graph_json) VALUES ($1, $2, $3, $4, $5)")
        .bind(workflow_id)
        .bind(user_id)
        .bind("Test Workflow")
        .bind("talos://test-module")
        .bind(graph_json)
        .execute(&ctx.db_pool)
        .await
        .unwrap();

    let entry_id = Uuid::new_v4();
    let error_msg = "WASM Runtime Panic".to_string();
    let payload = json!({"input": 123}); // payload is JSONB

    sqlx::query("INSERT INTO dead_letter_queue (id, workflow_id, execution_id, node_id, error_message, payload) VALUES ($1, $2, $3, $4, $5, $6)")
        .bind(entry_id)
        .bind(workflow_id)
        .bind(execution_id)
        .bind(node_id)
        .bind(error_msg)
        .bind(payload)
        .execute(&ctx.db_pool)
        .await
        .unwrap();

    // 2. Query DLQ
    let query = r#"
        query GetDLQ {
            deadLetterQueue {
                id
                workflowId
                errorMessage
                payload
            }
        }
    "#;
    let resp = client.execute(query).await;
    let data: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&resp.data).unwrap()).unwrap();

    let entries = data["deadLetterQueue"]
        .as_array()
        .expect("deadLetterQueue should be an array");
    assert!(!entries.is_empty());
    let entry = entries
        .iter()
        .find(|e| e["id"] == entry_id.to_string())
        .expect("Should find our entry");
    assert_eq!(entry["workflowId"], workflow_id.to_string());
    assert_eq!(entry["errorMessage"], "WASM Runtime Panic");
}

#[ignore = "references dropped wasm_modules/node_templates tables — port fixtures to unified `modules` table (Phase 5)"]
#[tokio::test]
async fn test_webhook_dlq_flow() {
    let ctx = setup_test_context().await;
    let user_id: Uuid = create_test_user(&ctx.auth_service, "webhook-dlq@example.com").await;
    let client = AuthenticatedClient::new(user_id, None, vec![], ctx.schema.clone());

    // 1. Seed a module first
    let template_id = Uuid::new_v4();
    sqlx::query("INSERT INTO node_templates (id, name, category, config_schema, code_template) VALUES ($1, $2, $3, $4, $5)")
        .bind(template_id)
        .bind("Test Template")
        .bind("http")
        .bind(json!({}))
        .bind("")
        .execute(&ctx.db_pool)
        .await
        .unwrap();

    let module_id = Uuid::new_v4();
    sqlx::query("INSERT INTO wasm_modules (id, name, content_hash, wasm_bytes, template_id, size_bytes) VALUES ($1, $2, $3, $4, $5, $6)")
        .bind(module_id)
        .bind("Test Module")
        .bind("hash_123")
        .bind(vec![0u8; 10])
        .bind(template_id)
        .bind(10)
        .execute(&ctx.db_pool)
        .await
        .unwrap();

    // 2. Seed a webhook trigger
    let trigger_id = Uuid::new_v4();
    sqlx::query("INSERT INTO webhook_triggers (id, user_id, name, module_id, verification_token, enabled) VALUES ($1, $2, $3, $4, $5, $6)")
        .bind(trigger_id)
        .bind(user_id)
        .bind("Test Trigger")
        .bind(module_id)
        .bind("tok_123")
        .bind(true)
        .execute(&ctx.db_pool)
        .await
        .unwrap();

    let entry_id = Uuid::new_v4();
    let drop_reason = "circuit_breaker".to_string();
    let payload = json!({"event": "push"}); // payload is JSONB
    let source_ip = "127.0.0.1".to_string();

    sqlx::query("INSERT INTO webhook_dlq (id, trigger_id, drop_reason, payload, source_ip) VALUES ($1, $2, $3, $4, $5::inet)")
        .bind(entry_id)
        .bind(trigger_id)
        .bind(drop_reason)
        .bind(payload)
        .bind(source_ip)
        .execute(&ctx.db_pool)
        .await
        .unwrap();

    // 3. Query Webhook DLQ
    let query = r#"
        query GetWebhookDLQ {
            webhookDeadLetterQueue {
                id
                triggerId
                dropReason
                payload
            }
        }
    "#;
    let resp = client.execute(query).await;
    let data: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&resp.data).unwrap()).unwrap();

    let entries = data["webhookDeadLetterQueue"]
        .as_array()
        .expect("webhookDeadLetterQueue should be an array");
    let entry = entries
        .iter()
        .find(|e| e["id"] == entry_id.to_string())
        .expect("Should find our entry");
    assert_eq!(entry["dropReason"], "circuit_breaker");

    // 4. Replay entry
    let mutation = r#"
        mutation Replay($id: UUID!) {
            replayWebhookDeadLetterEntry(id: $id)
        }
    "#;
    let _resp = client
        .execute_with_variables(mutation, json!({"id": entry_id}))
        .await;
}

#[ignore = "references dropped wasm_modules/node_templates tables — port fixtures to unified `modules` table (Phase 5)"]
#[tokio::test]
async fn test_approval_queue_and_resource_quotas() {
    let ctx = setup_test_context().await;
    let user_id: Uuid = create_test_user(&ctx.auth_service, "approval@example.com").await;
    let client = AuthenticatedClient::new(user_id, None, vec![], ctx.schema.clone());

    // 0. Seed an Organization
    let org_id = Uuid::new_v4();
    sqlx::query("INSERT INTO organizations (id, name, slug, owner_id) VALUES ($1, $2, $3, $4)")
        .bind(org_id)
        .bind("Test Org")
        .bind("test-org")
        .bind(user_id)
        .execute(&ctx.db_pool)
        .await
        .unwrap();

    sqlx::query("INSERT INTO organization_members (org_id, user_id, role) VALUES ($1, $2, $3)")
        .bind(org_id)
        .bind(user_id)
        .bind("owner")
        .execute(&ctx.db_pool)
        .await
        .unwrap();

    // 1. Seed necessary FKs for approvals
    let template_id = Uuid::new_v4();
    sqlx::query("INSERT INTO node_templates (id, name, category, config_schema, code_template) VALUES ($1, $2, $3, $4, $5)")
        .bind(template_id)
        .bind("Approval Template")
        .bind("integration")
        .bind(json!({}))
        .bind("")
        .execute(&ctx.db_pool)
        .await
        .unwrap();

    let module_id = Uuid::new_v4();
    sqlx::query("INSERT INTO wasm_modules (id, name, content_hash, wasm_bytes, template_id, size_bytes) VALUES ($1, $2, $3, $4, $5, $6)")
        .bind(module_id)
        .bind("Approval Module")
        .bind("approval_hash")
        .bind(vec![0u8; 10])
        .bind(template_id)
        .bind(10)
        .execute(&ctx.db_pool)
        .await
        .unwrap();

    let execution_id = Uuid::new_v4();
    sqlx::query("INSERT INTO module_executions (id, module_id, user_id, status, trigger_type) VALUES ($1, $2, $3, $4, $5)")
        .bind(execution_id)
        .bind(module_id)
        .bind(user_id)
        .bind("pending")
        .bind("manual")
        .execute(&ctx.db_pool)
        .await
        .unwrap();

    let workflow_id = Uuid::new_v4();
    sqlx::query("INSERT INTO workflows (id, user_id, name, module_uri, graph_json) VALUES ($1, $2, $3, $4, $5)")
        .bind(workflow_id)
        .bind(user_id)
        .bind("Approval Test Workflow")
        .bind("talos://approval-module")
        .bind("{}".to_string())
        .execute(&ctx.db_pool)
        .await
        .unwrap();

    let approval_id = Uuid::new_v4();
    let approval_node_id = Uuid::new_v4();
    sqlx::query("INSERT INTO execution_approvals (id, workflow_id, execution_id, node_id, required_for, status) VALUES ($1, $2, $3, $4, $5, $6)")
        .bind(approval_id)
        .bind(workflow_id)
        .bind(execution_id)
        .bind(approval_node_id)
        .bind(vec!["sensitive_operation".to_string()])
        .bind("pending")
        .execute(&ctx.db_pool)
        .await
        .unwrap();

    let query = r#"
        query GetApprovals {
            pendingApprovals {
                id
                status
            }
        }
    "#;
    let resp = client.execute(query).await;
    let data: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&resp.data).unwrap()).unwrap();
    let approvals = data["pendingApprovals"]
        .as_array()
        .expect("pendingApprovals should be an array");
    let approval = approvals
        .iter()
        .find(|a| a["id"] == approval_id.to_string())
        .expect("Should find our approval");
    assert_eq!(approval["status"], "pending");

    // 2. Test Resource Quotas
    sqlx::query("INSERT INTO resource_quotas (org_id, metric, max_limit) VALUES ($1, $2, $3)")
        .bind(org_id)
        .bind("cpu_cores")
        .bind(16i64)
        .execute(&ctx.db_pool)
        .await
        .unwrap();

    sqlx::query("INSERT INTO resource_quotas (org_id, metric, max_limit) VALUES ($1, $2, $3)")
        .bind(org_id)
        .bind("concurrent_executions")
        .bind(20i64)
        .execute(&ctx.db_pool)
        .await
        .unwrap();

    let quota_query = r#"
        query GetQuotas {
            resourceQuotas {
                cpuCores
                concurrentExecutions
            }
        }
    "#;
    let resp = client.execute(quota_query).await;
    let data: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&resp.data).unwrap()).unwrap();
    assert_eq!(data["resourceQuotas"]["cpuCores"], 16);
    assert_eq!(data["resourceQuotas"]["concurrentExecutions"], 20);
}
