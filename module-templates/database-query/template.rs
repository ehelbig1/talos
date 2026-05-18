use serde::Deserialize;
use talos_sdk_macros::talos_module;

#[derive(Deserialize)]
struct DatabaseInput {
    /// The SQL query to execute
    query: String,
    /// Optional parameters to bind to the query
    #[serde(default)]
    params: Vec<String>,
}

#[talos_module(world = "database-node")]
pub fn run(input: String) -> Result<String, String> {
    use talos::core::database;
    use talos::core::logging::{self, Level};

    logging::log(Level::Debug, "[database-query] Parsing input...");

    let db_input: DatabaseInput = match serde_json::from_str(&input) {
        Ok(val) => val,
        Err(e) => {
            let msg = format!("Failed to parse input JSON: {}", e);
            logging::log(Level::Error, &msg);
            return Err(msg);
        }
    };

    logging::log(
        Level::Info,
        &format!("[database-query] Executing query: {}", db_input.query),
    );

    match database::execute_query(&db_input.query, &db_input.params) {
        Ok(result) => {
            logging::log(
                Level::Info,
                &format!(
                    "[database-query] Query successful. Rows affected: {}, result bytes: {}",
                    result.rows_affected,
                    result.rows.len()
                ),
            );

            // Build output JSON by string concatenation to avoid deserializing
            // the rows JSON into a serde_json::Value tree (which uses 3x memory).
            // The rows string from the host is already valid JSON, so we embed
            // it directly into the output without parsing.
            let rows_json = if result.rows.is_empty() {
                "null"
            } else {
                &result.rows
            };
            let mut out = String::with_capacity(64 + rows_json.len());
            out.push_str(r#"{"success":true,"rows":"#);
            out.push_str(rows_json);
            out.push_str(r#","rows_affected":"#);
            out.push_str(&result.rows_affected.to_string());
            out.push_str(r#","error":null}"#);
            Ok(out)
        }
        Err(_e) => {
            // Retrieve the detailed error message from the host.
            let detail = database::get_last_error();
            let error_msg = if detail.is_empty() {
                format!("{:?}", _e)
            } else {
                detail
            };
            logging::log(
                Level::Error,
                &format!("[database-query] Query failed: {}", error_msg),
            );

            // Escape the error message for JSON embedding
            let escaped = error_msg
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\n");
            let mut out = String::with_capacity(80 + escaped.len());
            out.push_str(r#"{"success":false,"rows":null,"rows_affected":null,"error":""#);
            out.push_str(&escaped);
            out.push_str(r#""}"#);
            Ok(out)
        }
    }
}
