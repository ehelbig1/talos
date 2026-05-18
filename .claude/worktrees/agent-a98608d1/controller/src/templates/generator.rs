#![allow(dead_code)]
use anyhow::{bail, Result};
use handlebars::Handlebars;
use serde_json::Value as JsonValue;

pub struct TemplateGenerator {
    handlebars: Handlebars<'static>,
}

impl TemplateGenerator {
    pub fn new() -> Self {
        let mut handlebars = Handlebars::new();
        // Configure Handlebars for strict mode
        handlebars.set_strict_mode(true);
        // Don't escape HTML since we're generating Rust code
        handlebars.register_escape_fn(handlebars::no_escape);

        Self { handlebars }
    }

    /// Generate Rust code from template + config
    pub fn generate_code(&self, template_code: &str, config: &JsonValue) -> Result<String> {
        // Validate config is an object
        if !config.is_object() {
            bail!("Config must be a JSON object");
        }

        // Render template with Handlebars
        // Render the template; propagate any rendering error instead of panicking.
        let code = self
            .handlebars
            .render_template(template_code, config)
            .map_err(|e| anyhow::anyhow!(e))?;

        // Basic syntax validation (check for common issues)
        self.validate_generated_code(&code)?;

        Ok(code)
    }

    fn validate_generated_code(&self, code: &str) -> Result<()> {
        // Check for required elements in a valid WASM node

        if !code.contains("wit_bindgen::generate!") {
            bail!("Generated code missing wit_bindgen::generate! macro");
        }

        if !code.contains("impl Guest for") {
            bail!("Generated code missing Guest trait implementation");
        }

        if !code.contains("export!") {
            bail!("Generated code missing export! macro");
        }

        // Check for basic Rust syntax issues
        if code.contains("{{") || code.contains("}}") {
            bail!("Generated code contains unresolved template placeholders");
        }

        Ok(())
    }
}

impl Default for TemplateGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_simple_generation() {
        let generator = TemplateGenerator::new();

        let template = r#"
wit_bindgen::generate!({
    world: "automation-node",
});

struct {{NODE_NAME}};

impl Guest for {{NODE_NAME}} {
    fn run(input: String) -> Result<String, String> {
        Ok("{{OUTPUT}}".to_string())
    }
}

export!({{NODE_NAME}});
"#;

        let config = json!({
            "NODE_NAME": "TestNode",
            "OUTPUT": "Hello, World!"
        });

        let result = generator.generate_code(template, &config);
        assert!(result.is_ok());

        let code = result.expect("Template generation should succeed");
        assert!(code.contains("struct TestNode"));
        assert!(code.contains("Hello, World!"));
    }

    #[test]
    fn test_missing_placeholders() {
        let generator = TemplateGenerator::new();

        let template = "struct {{NODE_NAME}};";
        let config = json!({});

        let result = generator.generate_code(template, &config);
        assert!(result.is_err());
    }
}
