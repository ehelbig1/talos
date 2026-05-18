use async_graphql::*;
use controller::api::schema::QueryRoot;
use controller::engine::rhai_helpers::{evaluate_condition, extract_json_path};
use serde_json::json;
use uuid::Uuid;

#[tokio::test]
async fn test_rhai_expression_query() {
    // Mock user ID in context
    let user_id = Uuid::new_v4();

    let schema = Schema::build(QueryRoot::default(), EmptyMutation, EmptySubscription)
        .data(user_id)
        .finish();

    // Test simple expression
    let query = r#"
        query {
            testRhaiExpression(input: {
                script: "items.filter(|x| x > 1)",
                mockContext: "{\"items\": [1, 2, 3]}"
            }) {
                success
                output
                error
            }
        }
    "#;

    let res = schema.execute(query).await;
    assert!(res.errors.is_empty(), "GraphQL errors: {:?}", res.errors);

    let data = res.data.into_json().unwrap();
    let result = &data["testRhaiExpression"];

    assert!(result["success"].as_bool().unwrap());
    assert_eq!(result["output"].as_str().unwrap(), "[2,3]");
    assert!(result["error"].is_null());

    // Test error case
    let query_err = r#"
        query {
            testRhaiExpression(input: {
                script: "invalid syntax {",
                mockContext: "{}"
            }) {
                success
                output
                error
            }
        }
    "#;

    let res_err = schema.execute(query_err).await;
    let data_err = res_err.data.into_json().unwrap();
    let result_err = &data_err["testRhaiExpression"];

    assert!(!result_err["success"].as_bool().unwrap());
    assert!(result_err["error"].as_str().is_some());
}

#[tokio::test]
async fn test_rhai_expression_security_limits() {
    let user_id = Uuid::new_v4();
    let schema = Schema::build(QueryRoot::default(), EmptyMutation, EmptySubscription)
        .data(user_id)
        .finish();

    // Test infinite loop/large ops
    let query_limit = r#"
        query {
            testRhaiExpression(input: {
                script: "let x = 0; loop { x += 1; }",
                mockContext: "{}"
            }) {
                success
                output
                error
            }
        }
    "#;

    let res_limit = schema.execute(query_limit).await;
    let data_limit = res_limit.data.into_json().unwrap();
    let result_limit = &data_limit["testRhaiExpression"];

    assert!(!result_limit["success"].as_bool().unwrap());
    assert!(result_limit["error"]
        .as_str()
        .unwrap()
        .contains("Too many operations"));
}

#[test]
fn test_evaluate_condition_basic() {
    let context = json!({
        "status": "success",
        "count": 10
    });

    assert!(evaluate_condition("status == \"success\"", &context));
    assert!(evaluate_condition("count > 5", &context));
    assert!(!evaluate_condition("count < 5", &context));
}

#[test]
fn test_evaluate_condition_with_nested_ctx() {
    let context = json!({
        "data": {
            "value": 42
        }
    });

    // Test both direct access and 'ctx' alias
    assert!(evaluate_condition("data.value == 42", &context));
    assert!(evaluate_condition("ctx.data.value == 42", &context));
}

#[test]
fn test_extract_json_path() {
    let context = json!({
        "data": {
            "nested": {
                "val": "hello"
            }
        },
        "list": [10, 20, 30]
    });

    assert_eq!(
        extract_json_path("data.nested.val", &context),
        Some(json!("hello"))
    );
    assert_eq!(extract_json_path("list[1]", &context), Some(json!(20)));
}
