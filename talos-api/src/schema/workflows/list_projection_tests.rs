//! Drives `queries::list_projection` through a real async-graphql execution,
//! with the production `Workflow` type, so fragments and aliases are covered.
//! A sibling file, not a module inside `queries.rs`: check 22 reads every
//! `async fn` there as a resolver.
use super::queries::list_projection;
use crate::schema::types::Workflow;
use async_graphql::{Context, EmptyMutation, EmptySubscription, Object, Schema};
use uuid::Uuid;

struct Root;

#[Object]
impl Root {
    /// Builds rows exactly as the `workflows` resolver does from a list
    /// query: `graph_json` only when projected, SQL counts only when
    /// projected (here `(Some(2), Some(1))`).
    async fn workflows(&self, ctx: &Context<'_>) -> Vec<Workflow> {
        let p = list_projection(&ctx.look_ahead());
        vec![Workflow {
            id: Uuid::nil(),
            name: "w".into(),
            graph_json: p
                .graph_json
                .then(|| r#"{"nodes":[{},{}],"edges":[{}]}"#.to_string()),
            graph_counts: p.graph_counts.then_some((Some(2), Some(1))),
            graph_version: 1,
            max_concurrent_executions: None,
            intent: None,
            actor_id: None,
        }]
    }
}

async fn run(q: &str) -> serde_json::Value {
    let schema = Schema::new(Root, EmptyMutation, EmptySubscription);
    let resp = schema.execute(q).await;
    assert!(resp.errors.is_empty(), "{q}: {:?}", resp.errors);
    resp.data.into_json().unwrap()
}

#[tokio::test]
async fn counts_only_skips_the_graph_and_serves_sql_counts() {
    let d = run("{ workflows { nodeCount edgeCount } }").await;
    assert_eq!(d["workflows"][0]["nodeCount"], 2);
    assert_eq!(d["workflows"][0]["edgeCount"], 1);
}

#[tokio::test]
async fn graph_json_is_loaded_through_fragments_and_aliases() {
    for q in [
        "{ workflows { graphJson } }",
        "{ workflows { g: graphJson } }",
        "{ workflows { ...F } } fragment F on Workflow { graphJson }",
        "{ workflows { ... on Workflow { graphJson nodeCount } } }",
    ] {
        let d = run(q).await;
        let w = &d["workflows"][0];
        let g = w.get("graphJson").or_else(|| w.get("g")).unwrap();
        assert!(g.as_str().unwrap().contains("nodes"), "{q}");
    }
}

#[test]
fn a_workflow_without_sql_counts_derives_them_from_its_graph() {
    let w = Workflow {
        id: Uuid::nil(),
        name: "w".into(),
        graph_json: Some(r#"{"nodes":[1,2,3],"edges":"bad"}"#.into()),
        graph_counts: None,
        graph_version: 1,
        max_concurrent_executions: None,
        intent: None,
        actor_id: None,
    };
    assert_eq!(w.counts(), (Some(3), None));
}
