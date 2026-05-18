use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;
use std::env;
use std::sync::Arc;
use tokio::time::{sleep, Duration};

use super::ModuleRegistry;

#[derive(Deserialize)]
struct CatalogResponse {
    repositories: Vec<String>,
}

#[derive(Deserialize)]
struct TagsResponse {
    name: String,
    tags: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct ManifestResponse {
    config: ManifestConfig,
}

#[derive(Deserialize)]
struct ManifestConfig {
    digest: String,
}

pub async fn start_registry_sync_loop(registry: Arc<ModuleRegistry>) {
    let registry_url =
        env::var("TALOS_REGISTRY_URL").unwrap_or_else(|_| "http://registry:5000".to_string());

    let client = Client::new();

    // Give the system a few seconds to start up before the first sync
    sleep(Duration::from_secs(5)).await;

    loop {
        tracing::info!("Starting OCI registry sync from {}", registry_url);
        if let Err(e) = sync_registry(&client, &registry_url, &registry).await {
            tracing::error!("Registry sync failed: {:#}", e);
        }

        // Wait before syncing again (e.g., every 5 minutes)
        sleep(Duration::from_secs(300)).await;
    }
}

async fn sync_registry(client: &Client, registry_url: &str, db: &ModuleRegistry) -> Result<()> {
    // 1. Fetch catalog
    let catalog_url = format!("{}/v2/_catalog", registry_url);
    let catalog_resp = client.get(&catalog_url).send().await?;

    if !catalog_resp.status().is_success() {
        // Registry might not be ready or empty
        tracing::warn!(
            "Failed to fetch catalog from {}: {}",
            catalog_url,
            catalog_resp.status()
        );
        return Ok(());
    }

    let catalog: CatalogResponse = catalog_resp
        .json()
        .await
        .context("Failed to parse catalog")?;

    for repo in catalog.repositories {
        // Only sync repos that are meant for Talos
        if !repo.starts_with("talos-tools/") {
            continue;
        }

        // 2. Fetch tags
        let tags_url = format!("{}/v2/{}/tags/list", registry_url, repo);
        let tags_resp = client.get(&tags_url).send().await?;
        if !tags_resp.status().is_success() {
            continue;
        }

        let tags_data: TagsResponse = tags_resp.json().await?;
        let tags = tags_data.tags.unwrap_or_default();

        for tag in tags {
            if let Err(e) = sync_repo_tag(client, registry_url, &repo, &tag, db).await {
                tracing::error!("Failed to sync {}/{}:{}: {}", registry_url, repo, tag, e);
            }
        }
    }

    Ok(())
}

async fn sync_repo_tag(
    client: &Client,
    registry_url: &str,
    repo: &str,
    tag: &str,
    db: &ModuleRegistry,
) -> Result<()> {
    // 3. Fetch manifest
    let manifest_url = format!("{}/v2/{}/manifests/{}", registry_url, repo, tag);
    let manifest_resp = client
        .get(&manifest_url)
        .header("Accept", "application/vnd.oci.image.manifest.v1+json")
        .send()
        .await?;

    if !manifest_resp.status().is_success() {
        anyhow::bail!("Failed to fetch manifest: {}", manifest_resp.status());
    }

    let manifest: ManifestResponse = manifest_resp.json().await.context("Parse manifest")?;
    let config_digest = manifest.config.digest;

    // 4. Fetch config blob
    let blob_url = format!("{}/v2/{}/blobs/{}", registry_url, repo, config_digest);
    let blob_resp = client.get(&blob_url).send().await?;

    if !blob_resp.status().is_success() {
        anyhow::bail!("Failed to fetch config blob: {}", blob_resp.status());
    }

    let config_bytes = blob_resp.bytes().await?;

    // Parse as talos.json
    let talos_manifest: serde_json::Value =
        serde_json::from_slice(&config_bytes).context("Config blob is not valid JSON")?;

    // Extract fields
    let name = talos_manifest
        .get("display_name")
        .or_else(|| talos_manifest.get("name"))
        .and_then(|v| v.as_str());

    let name = match name {
        Some(n) => n,
        None => {
            tracing::warn!(
                "Skipping {}/{} because manifest has no name field (likely pushed with old script)",
                repo,
                tag
            );
            return Ok(());
        }
    };

    let category = talos_manifest
        .get("category")
        .and_then(|v| v.as_str())
        .unwrap_or("Custom");

    let description = talos_manifest
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let default_schema = serde_json::json!({ "type": "object", "properties": {} });
    let mut config_schema = talos_manifest
        .get("config_schema")
        .cloned()
        .unwrap_or(default_schema);

    // Embed the default allowed hosts inside the config schema so we can access it during instantiation
    if let Some(hosts) = talos_manifest.get("allowed_hosts") {
        if let Some(obj) = config_schema.as_object_mut() {
            obj.insert("talos_allowed_hosts".to_string(), hosts.clone());
        }
    }

    // OCI URL format matching what the worker expects
    // e.g. oci://registry:5000/talos-tools/text-analyzer:v1.0.0
    // Wait, the worker pulls using the internal URL
    let host_and_port = registry_url
        .trim_start_matches("http://")
        .trim_start_matches("https://");

    // Ensure the repository name is lowercased and spaces are replaced with hyphens
    // as required by OCI registry naming conventions
    let repo_clean = repo.to_lowercase().replace(" ", "-");
    let oci_url = format!("oci://{}/{}:{}", host_and_port, repo_clean, tag);

    // 5. Upsert into database
    let _result = sqlx::query(
        "INSERT INTO node_templates (name, category, description, config_schema, code_template, oci_url)
         VALUES ($1, $2, $3, $4, '', $5)
         ON CONFLICT (name) DO UPDATE SET
             category = EXCLUDED.category,
             description = EXCLUDED.description,
             config_schema  = EXCLUDED.config_schema,
             oci_url        = EXCLUDED.oci_url"
    )
    .bind(name)
    .bind(category)
    .bind(description)
    .bind(&config_schema)
    .bind(&oci_url)
    .execute(&db.db_pool)
    .await?;

    tracing::debug!("Successfully synced {} from OCI registry", name);

    Ok(())
}
