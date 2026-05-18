use serde::{Deserialize, Serialize};
use serde_json::Value;

// Generate bindings for the database-node world
wit_bindgen::generate!({
    world: "database-node",
    path: "wit/talos.wit",
});

use talos::core::logging::{self, Level};
use talos::core::database::{self, QueryResult};

#[derive(Deserialize)]
struct DatabaseInput {
    // The SQL query to execute
    query: String,
    // Optional parameters to bind to the query
    #[serde(default)]
    params: Vec<String>,
}

#[derive(Serialize)]
struct DatabaseOutput {
    success: bool,
    rows: Option<Value>,
    rows_affected: Option<u64>,
    error: Option<String>,
}

struct DatabaseNode;

impl Guest for DatabaseNode {
    fn run(input: String) -> Result<String, String> {
        logging::log(Level::Debug, "[database-query] Parsing input...");
        
        let db_input: DatabaseInput = match serde_json::from_str(&input) {
            Ok(val) => val,
            Err(e) => {
                let msg = format!("Failed to parse input JSON: {}", e);
                logging::log(Level::Error, &msg);
                return Err(msg);
            }
        };

        logging::log(Level::Info, &format!("[database-query] Executing query: {}", db_input.query));

        let mut output = DatabaseOutput {
            success: false,
            rows: None,
            rows_affected: None,
            error: None,
        };

        match database::execute_query(&db_input.query, &db_input.params) {
            Ok(result) => {
                logging::log(Level::Info, &format!("[database-query] Query successful. Rows affected: {}", result.rows_affected));
                output.success = true;
                output.rows_affected = Some(result.rows_affected);
                
                // Try to parse the rows back into JSON
                if !result.rows.is_empty() {
                    match serde_json::from_str::<Value>(&result.rows) {
                        Ok(json_rows) => {
                            output.rows = Some(json_rows);
                        },
                        Err(e) => {
                            logging::log(Level::Warn, &format!("[database-query] Failed to parse rows as JSON: {}", e));
                            // We still return success but maybe wrap rows in a string value or just error?
                            output.rows = Some(Value::String(result.rows.clone()));
                        }
                    }
                }
            },
            Err(e) => {
                let error_msg = format!("{:?}", e);
                logging::log(Level::Error, &format!("[database-query] Query failed: {}", error_msg));
                output.error = Some(error_msg);
            }
        }

        match serde_json::to_string(&output) {
            Ok(json) => Ok(json),
            Err(e) => Err(format!("Failed to serialize output: {}", e)),
        }
    }
}

export!(DatabaseNode);
