use talos_sdk_macros::talos_module;

#[talos_module(world = "filesystem-node")]
fn run(input: String) -> Result<String, String> {
use talos::core::logging::{self, Level};
use talos::core::files;
use talos::core::data_transform;
use talos::core::json;

        // Parse input
        let input_json: serde_json::Value = serde_json::from_str(&input)
            .map_err(|e| format!("Invalid JSON input: {}", e))?;

        // Get config
        let config = input_json.get("config")
            .ok_or("Missing config")?;

        let input_file = config.get("input_file")
            .and_then(|v| v.as_str())
            .ok_or("Missing input_file")?;

        let output_file = config.get("output_file")
            .and_then(|v| v.as_str())
            .ok_or("Missing output_file")?;

        let input_format = config.get("input_format")
            .and_then(|v| v.as_str())
            .unwrap_or("csv");

        let output_format = config.get("output_format")
            .and_then(|v| v.as_str())
            .unwrap_or("json");

        let csv_has_headers = config.get("csv_has_headers")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        logging::log(Level::Info, &format!("Reading file: {}", input_file));

        // Read input file
        let input_bytes = files::read(input_file)
            .map_err(|e| format!("Failed to read input file: {:?}", e))?;

        let input_content = String::from_utf8(input_bytes)
            .map_err(|e| format!("Input file is not valid UTF-8: {}", e))?;

        // Convert to JSON intermediate format
        let json_data = match input_format {
            "csv" => {
                let csv_options = data_transform::CsvOptions {
                    delimiter: None,
                    has_headers: csv_has_headers,
                    skip_rows: None,
                };
                data_transform::csv_to_json(&input_content, Some(&csv_options))
                    .map_err(|e| format!("Failed to parse CSV: {:?}", e))?
            }
            "xml" => {
                data_transform::xml_to_json(&input_content)
                    .map_err(|e| format!("Failed to parse XML: {:?}", e))?
            }
            "json" => {
                // Validate JSON
                json::parse(&input_content)
                    .map_err(|e| format!("Failed to parse JSON: {:?}", e))?;
                input_content.clone()
            }
            _ => return Err(format!("Unsupported input format: {}", input_format))
        };

        logging::log(Level::Info, &format!("Parsed {} data successfully", input_format));

        // Convert from JSON to output format
        let output_content = match output_format {
            "json" => {
                json::prettify(&json_data)
                    .map_err(|e| format!("Failed to prettify JSON: {:?}", e))?
            }
            "csv" => {
                let csv_options = data_transform::CsvOptions {
                    delimiter: None,
                    has_headers: csv_has_headers,
                    skip_rows: None,
                };
                data_transform::json_to_csv(&json_data, Some(&csv_options))
                    .map_err(|e| format!("Failed to generate CSV: {:?}", e))?
            }
            "xml" => {
                data_transform::json_to_xml(&json_data, "root")
                    .map_err(|e| format!("Failed to generate XML: {:?}", e))?
            }
            _ => return Err(format!("Unsupported output format: {}", output_format))
        };

        logging::log(Level::Info, &format!("Writing file: {}", output_file));

        // Write output file
        files::write(output_file, output_content.as_bytes())
            .map_err(|e| format!("Failed to write output file: {:?}", e))?;

        // Return summary
        let result = serde_json::json!({
            "success": true,
            "input_file": input_file,
            "output_file": output_file,
            "input_format": input_format,
            "output_format": output_format,
            "bytes_read": input_content.len(),
            "bytes_written": output_content.len()
        });

        serde_json::to_string(&result)
            .map_err(|e| format!("Failed to serialize result: {}", e))
    }
