# Secrets Management Architecture

## Overview

Talos requires secure storage and retrieval of sensitive data like API keys, verification tokens, OAuth credentials, and signing secrets. This document outlines a defense-in-depth approach to secrets management.

## Security Requirements

1. **Encryption at Rest** - Secrets encrypted in database
2. **Encryption in Transit** - TLS for all communication
3. **Access Control** - Only authorized services/users can access secrets
4. **Audit Trail** - Log all secret access/modifications
5. **Rotation Support** - Ability to update secrets without downtime
6. **No Hardcoding** - Secrets never in WASM modules or source code
7. **Secure Defaults** - Fail secure, require explicit permissions

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                     Application Layer                     │
│  ┌─────────────┐    ┌──────────────┐   ┌──────────────┐ │
│  │  Frontend   │───▶│  Controller  │◀──│ WASM Runtime │ │
│  │  (no access)│    │              │   │  (no direct  │ │
│  └─────────────┘    └───────┬──────┘   │   access)    │ │
│                             │          └──────────────┘ │
└─────────────────────────────┼────────────────────────────┘
                              │
                    ┌─────────▼──────────┐
                    │  Secrets Manager   │
                    │                    │
                    │  - Encryption      │
                    │  - Access Control  │
                    │  - Audit Log       │
                    └─────────┬──────────┘
                              │
                    ┌─────────▼──────────┐
                    │    PostgreSQL      │
                    │                    │
                    │  secrets table     │
                    │  (encrypted data)  │
                    └────────────────────┘
```

## Database Schema

```sql
-- Secrets table with encryption
CREATE TABLE secrets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,  -- User-friendly name like "slack-bot-token"
    key_path TEXT UNIQUE NOT NULL,  -- Hierarchical path like "slack/production/bot-token"

    -- Encrypted data (AES-256-GCM)
    encrypted_value BYTEA NOT NULL,
    encryption_key_id TEXT NOT NULL,  -- Which key was used (for rotation)
    nonce BYTEA NOT NULL,  -- Unique per encryption

    -- Metadata
    description TEXT,
    created_by UUID,  -- User who created it
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ,  -- Optional expiration

    -- Access control
    owner_user_id UUID,
    allowed_modules UUID[],  -- Which WASM modules can access this

    -- Audit
    last_accessed_at TIMESTAMPTZ,
    access_count INTEGER DEFAULT 0
);

-- Audit log for secret access
CREATE TABLE secret_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_id UUID REFERENCES secrets(id) ON DELETE CASCADE,
    action TEXT NOT NULL,  -- 'create', 'read', 'update', 'delete', 'rotate'
    actor_type TEXT NOT NULL,  -- 'user', 'module', 'system'
    actor_id UUID,
    module_id UUID,  -- If accessed by WASM module
    success BOOLEAN NOT NULL,
    error_message TEXT,
    ip_address INET,
    timestamp TIMESTAMPTZ DEFAULT NOW()
);

-- Master encryption keys (stored encrypted by system key)
CREATE TABLE encryption_keys (
    id TEXT PRIMARY KEY,  -- 'v1', 'v2', etc.
    encrypted_key BYTEA NOT NULL,  -- Encrypted DEK
    algorithm TEXT DEFAULT 'AES-256-GCM',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    rotated_at TIMESTAMPTZ,
    active BOOLEAN DEFAULT true
);

CREATE INDEX idx_secrets_key_path ON secrets(key_path);
CREATE INDEX idx_secrets_owner ON secrets(owner_user_id);
CREATE INDEX idx_audit_log_secret ON secret_audit_log(secret_id);
CREATE INDEX idx_audit_log_timestamp ON secret_audit_log(timestamp);
```

## Encryption Strategy

> **Current state (per-ORG root DEKs, formats v3/v4).** The code samples below
> are illustrative and predate three changes — read them as the *shape*, not the
> literal current implementation:
> 1. **Per-context key derivation.** A DEK is the derivation *root*, not the data
>    key. Each row is sealed under a per-context subkey
>    `HKDF-SHA256(ikm = DEK, salt = label, info = aad_context)` where the context
>    is the row's identity (secret_id / actor_id‖key / execution_id / per-slot
>    tag) — the same bytes bound as AES-GCM AAD. Bounds the per-key message count
>    to ~1 so the random-96-bit-nonce birthday limit is never approached.
> 2. **Per-ORGANIZATION root DEKs.** `encryption_keys.org_id` scopes DEKs: one
>    global DEK (`org_id IS NULL`) plus one active DEK per organization. Writers
>    seal under the writer-org's DEK (format `AAD_FORMAT_V4_ORG_DERIVED = 4`) when
>    an org is resolvable, else the global DEK (`AAD_FORMAT_V3_DERIVED = 3`) — so a
>    compromised root key is bounded to one tenant, not the whole deployment.
>    Decrypt is identical for v3/v4 (the row's `*_key_id` names the DEK); a per-row
>    `*_format` column selects the scheme and `SecretsManager::decrypt_versioned`
>    handles v0/v1/v2/v3/v4 (lazy migration, zero backfill). Existing rows migrate
>    via per-table `re_encrypt_*_to_org` sweeps (platform-admin mutations); the
>    `dekMigrationStatus` query reports remaining work. NOTE: checkpoint + worker
>    secret-envelope + OTLP-header encryption use a *separate* root
>    (`WORKER_SHARED_KEY` / `user_id`), not the DEK, and are NOT per-org.
> 3. **Plaintext hygiene.** Decrypted values and derived subkeys are held in
>    `Zeroizing` so they are wiped on drop, including error branches.

### Envelope Encryption Pattern

```
┌────────────────────────────────────────────────────┐
│  KEK (Key Encryption Key) — pluggable provider     │
│  via `KekProvider` trait                           │
│  • PRODUCTION: VaultTransitProvider                │
│      KEK lives in Vault transit; controller never  │
│      sees it. Wrap/unwrap = HTTPS call to Vault.   │
│      KEK_PROVIDER=vault                            │
│  • DEV: EnvKekProvider                             │
│      32-byte AES key from TALOS_MASTER_KEY env var.│
│      KEK_PROVIDER=env (default for dev)            │
└───────────────────┬────────────────────────────────┘
                    │ wraps
                    ▼
    ┌───────────────────────────────────┐
    │  Data Encryption Keys (DEKs)      │
    │  - Stored in encryption_keys      │
    │  - PER-ORG (encryption_keys.      │
    │    org_id) + a global fallback    │
    │  - Wrapped opaquely by KEK        │
    │    provider (wire format =        │
    │    provider's choice)             │
    │  - Rotatable independently        │
    └──────────────┬────────────────────┘
                   │ encrypts (per-row)
                   ▼
        ┌──────────────────────────────────────────┐
        │  Every column with user data:            │
        │  - secrets, oauth_tokens                 │
        │  - actor_memory.value_enc                │
        │  - module_executions.{input,output,      │
        │       trigger_metadata}_enc              │
        │  - workflow_executions.output_data_enc   │
        │  Each ciphertext has a unique nonce.     │
        └──────────────────────────────────────────┘
```

### Why Envelope Encryption?

1. **Key Rotation** - Can rotate DEKs without re-encrypting all secrets
2. **Performance** - Decrypt DEK once, use for multiple secrets
3. **Separation** - Master key lives outside database
4. **Auditing** - Track which key version encrypted each secret

## Implementation

### Secrets Manager Service

```rust
// controller/src/secrets/mod.rs

use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, NewAead};
use sqlx::{Pool, Postgres};
use uuid::Uuid;

pub struct SecretsManager {
    db_pool: Pool<Postgres>,
    master_key: Key,  // Loaded from env
}

impl SecretsManager {
    /// Create new secrets manager with master key from environment
    pub fn new(db_pool: Pool<Postgres>) -> Result<Self> {
        let master_key_hex = std::env::var("TALOS_MASTER_KEY")
            .expect("TALOS_MASTER_KEY environment variable must be set");

        let master_key_bytes = hex::decode(&master_key_hex)?;
        let master_key = Key::from_slice(&master_key_bytes);

        Ok(Self {
            db_pool,
            master_key: master_key.clone(),
        })
    }

    /// Store a new secret
    pub async fn create_secret(
        &self,
        key_path: &str,
        value: &str,
        creator_user_id: Uuid,
        allowed_modules: Vec<Uuid>,
    ) -> Result<Uuid> {
        // 1. Get active DEK (or create one)
        let dek = self.get_active_dek().await?;

        // 2. Encrypt the secret value
        let cipher = Aes256Gcm::new(&dek.key);
        let nonce = Nonce::from_slice(&generate_random_nonce());
        let encrypted_value = cipher
            .encrypt(nonce, value.as_bytes())
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        // 3. Store in database
        let secret_id = sqlx::query_scalar!(
            r#"
            INSERT INTO secrets (
                key_path, encrypted_value, encryption_key_id,
                nonce, created_by, allowed_modules
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id
            "#,
            key_path,
            &encrypted_value,
            &dek.id,
            nonce.as_slice(),
            creator_user_id,
            &allowed_modules
        )
        .fetch_one(&self.db_pool)
        .await?;

        // 4. Audit log
        self.log_audit(secret_id, "create", "user", Some(creator_user_id), None, true).await?;

        Ok(secret_id)
    }

    /// Retrieve and decrypt a secret
    pub async fn get_secret(
        &self,
        key_path: &str,
        requestor: SecretRequestor,
    ) -> Result<String> {
        // 1. Fetch from database
        let record = sqlx::query!(
            r#"
            SELECT id, encrypted_value, encryption_key_id, nonce, allowed_modules
            FROM secrets
            WHERE key_path = $1
            "#,
            key_path
        )
        .fetch_optional(&self.db_pool)
        .await?
        .ok_or_else(|| anyhow!("Secret not found: {}", key_path))?;

        // 2. Check access permissions
        match &requestor {
            SecretRequestor::Module(module_id) => {
                if let Some(allowed) = &record.allowed_modules {
                    if !allowed.contains(module_id) {
                        self.log_audit(
                            record.id,
                            "read",
                            "module",
                            None,
                            Some(*module_id),
                            false
                        ).await?;
                        return Err(anyhow!("Module not authorized to access this secret"));
                    }
                }
            }
            SecretRequestor::User(user_id) => {
                // Users can access secrets they own or admin users
                // (Add additional checks here)
            }
            SecretRequestor::System => {
                // System has full access
            }
        }

        // 3. Get DEK and decrypt
        let dek = self.get_dek(&record.encryption_key_id).await?;
        let cipher = Aes256Gcm::new(&dek.key);
        let nonce = Nonce::from_slice(&record.nonce);

        let decrypted_bytes = cipher
            .decrypt(nonce, record.encrypted_value.as_ref())
            .map_err(|e| anyhow!("Decryption failed: {}", e))?;

        let secret_value = String::from_utf8(decrypted_bytes)?;

        // 4. Update access stats
        sqlx::query!(
            r#"
            UPDATE secrets
            SET last_accessed_at = NOW(), access_count = access_count + 1
            WHERE id = $1
            "#,
            record.id
        )
        .execute(&self.db_pool)
        .await?;

        // 5. Audit log
        let (actor_type, actor_id, module_id) = match requestor {
            SecretRequestor::Module(mid) => ("module", None, Some(mid)),
            SecretRequestor::User(uid) => ("user", Some(uid), None),
            SecretRequestor::System => ("system", None, None),
        };

        self.log_audit(record.id, "read", actor_type, actor_id, module_id, true).await?;

        Ok(secret_value)
    }

    /// Rotate a secret (update value)
    pub async fn rotate_secret(
        &self,
        key_path: &str,
        new_value: &str,
        rotator_user_id: Uuid,
    ) -> Result<()> {
        // Similar to create_secret but UPDATE instead of INSERT
        // Use new nonce, potentially new DEK
        // Audit log the rotation
        Ok(())
    }

    /// Delete a secret
    pub async fn delete_secret(&self, key_path: &str, deleter_user_id: Uuid) -> Result<()> {
        let secret_id = sqlx::query_scalar!(
            "DELETE FROM secrets WHERE key_path = $1 RETURNING id",
            key_path
        )
        .fetch_one(&self.db_pool)
        .await?;

        self.log_audit(secret_id, "delete", "user", Some(deleter_user_id), None, true).await?;

        Ok(())
    }

    // Private helper methods
    async fn get_active_dek(&self) -> Result<DataEncryptionKey> {
        // Fetch from encryption_keys table, decrypt with master key
        todo!()
    }

    async fn get_dek(&self, key_id: &str) -> Result<DataEncryptionKey> {
        // Fetch specific DEK, decrypt with master key
        todo!()
    }

    async fn log_audit(
        &self,
        secret_id: Uuid,
        action: &str,
        actor_type: &str,
        actor_id: Option<Uuid>,
        module_id: Option<Uuid>,
        success: bool,
    ) -> Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO secret_audit_log (
                secret_id, action, actor_type, actor_id, module_id, success
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            secret_id,
            action,
            actor_type,
            actor_id,
            module_id,
            success
        )
        .execute(&self.db_pool)
        .await?;

        Ok(())
    }
}

pub enum SecretRequestor {
    User(Uuid),
    Module(Uuid),
    System,
}

struct DataEncryptionKey {
    id: String,
    key: Key,
}

fn generate_random_nonce() -> [u8; 12] {
    use rand::Rng;
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill(&mut nonce);
    nonce
}
```

## Usage in WASM Modules

### Problem: WASM can't directly access secrets

**Bad approach (insecure):**
```rust
// DON'T DO THIS - hardcoded secret in WASM
let api_key = "sk-1234567890abcdef";
```

**Good approach (runtime injection):**

```rust
// WASM module receives secret from runtime via config
impl Guest for MyNode {
    fn run(input: String) -> Result<String, String> {
        // Secrets are injected via special syntax in config
        let api_key = "{{secret:openai/api-key}}";  // Template syntax

        // At runtime, this is replaced with actual secret
        make_api_call(api_key, input)
    }
}
```

**How it works:**

1. User creates node with config: `{ "API_KEY": "{{secret:openai/api-key}}" }`
2. When compiling template, detect secret references
3. Store secret reference in module metadata
4. At runtime, before executing WASM:
   ```rust
   let config = module.config;
   for (key, value) in config {
       if value.starts_with("{{secret:") {
           let secret_path = extract_secret_path(value);
           let secret_value = secrets_manager
               .get_secret(secret_path, SecretRequestor::Module(module.id))
               .await?;
           config[key] = secret_value;
       }
   }
   ```
5. Pass resolved config to WASM

### Secret Lifecycle in Node Creation

```typescript
// Frontend: User creates Slack webhook listener
const config = {
  VERIFICATION_TOKEN: "{{secret:slack/webhook/verification-token}}"
};

// Backend: Detects secret reference
const secretRefs = extractSecretReferences(config);
// => ["slack/webhook/verification-token"]

// Ensure secret exists or prompt user to create it
for (const secretPath of secretRefs) {
  const exists = await secretsManager.secretExists(secretPath);
  if (!exists) {
    throw new Error(`Secret not found: ${secretPath}. Please create it first.`);
  }
}

// Store module with secret reference intact
await createModule({
  config: config,  // Keeps template syntax
  allowedSecrets: secretRefs  // Grants permission
});
```

## GraphQL API for Secrets

```graphql
type Secret {
  id: UUID!
  keyPath: String!
  description: String
  createdAt: DateTime!
  lastAccessedAt: DateTime
  accessCount: Int!
  # Never expose the actual secret value via GraphQL!
}

type SecretAuditLog {
  id: UUID!
  action: String!
  actorType: String!
  timestamp: DateTime!
  success: Boolean!
}

input CreateSecretInput {
  keyPath: String!
  value: String!  # Only accepted over HTTPS
  description: String
  allowedModules: [UUID!]
  expiresAt: DateTime
}

input UpdateSecretInput {
  keyPath: String!
  value: String!  # Rotation
}

type Mutation {
  createSecret(input: CreateSecretInput!): Secret!
  updateSecret(input: UpdateSecretInput!): Secret!
  deleteSecret(keyPath: String!): Boolean!
}

type Query {
  secrets: [Secret!]!  # List user's secrets (no values)
  secret(keyPath: String!): Secret!
  secretAuditLog(secretId: UUID!): [SecretAuditLog!]!
}
```

## Frontend UI for Secrets Management

```tsx
// frontend/src/components/secrets/SecretsManager.tsx

export function SecretsManager() {
  const [secrets, setSecrets] = useState([]);
  const [showCreate, setShowCreate] = useState(false);

  return (
    <div>
      <h2>Secrets Management</h2>

      <button onClick={() => setShowCreate(true)}>
        + Create New Secret
      </button>

      <table>
        <thead>
          <tr>
            <th>Key Path</th>
            <th>Description</th>
            <th>Last Accessed</th>
            <th>Access Count</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {secrets.map(secret => (
            <tr key={secret.id}>
              <td><code>{secret.keyPath}</code></td>
              <td>{secret.description}</td>
              <td>{formatDate(secret.lastAccessedAt)}</td>
              <td>{secret.accessCount}</td>
              <td>
                <button onClick={() => rotateSecret(secret)}>Rotate</button>
                <button onClick={() => deleteSecret(secret)}>Delete</button>
                <button onClick={() => viewAuditLog(secret)}>Audit Log</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {showCreate && (
        <CreateSecretDialog
          onClose={() => setShowCreate(false)}
          onCreate={(secret) => setSecrets([...secrets, secret])}
        />
      )}
    </div>
  );
}
```

## Integration with Node Builder

```tsx
// When creating Slack webhook listener:
<ConfigForm
  schema={schema}
  value={config}
  onChange={setConfig}
/>

// If field is marked as "secret" in schema:
{
  "VERIFICATION_TOKEN": {
    "type": "string",
    "format": "secret",  // Special format
    "secretPath": "slack/webhook/verification-token"
  }
}

// Render special input:
<SecretInput
  label="Verification Token"
  secretPath="slack/webhook/verification-token"
  value={config.VERIFICATION_TOKEN}
  onChange={(ref) => setConfig({
    ...config,
    VERIFICATION_TOKEN: ref  // "{{secret:slack/webhook/verification-token}}"
  })}
/>
```

## Security Best Practices

### 1. Master Key Management

**Development:**
```bash
# Generate master key
openssl rand -hex 32 > master-key.txt

# Set environment variable
export TALOS_MASTER_KEY=$(cat master-key.txt)
```

**Production:**
Use cloud provider secrets managers:
- AWS: Secrets Manager or Parameter Store
- GCP: Secret Manager
- Azure: Key Vault

```bash
# Fetch from AWS Secrets Manager
export TALOS_MASTER_KEY=$(aws secretsmanager get-secret-value \
  --secret-id talos/master-key \
  --query SecretString \
  --output text)
```

### 2. Never Log Secrets

```rust
// BAD
log::info!("Using API key: {}", api_key);

// GOOD
log::info!("Using API key: [REDACTED]");
log::debug!("API key length: {}", api_key.len());  // OK for debugging
```

### 3. Audit Everything

Every secret access is logged with:
- Who accessed it (user/module/system)
- When it was accessed
- Success or failure
- Source IP (if applicable)

### 4. Principle of Least Privilege

```rust
// When creating module, specify exactly which secrets it needs
allowed_modules: vec![module_id],

// WASM can only access secrets it's explicitly granted
```

### 5. Expiration & Rotation

```sql
-- Secrets can have expiration dates
expires_at: Some(now + 90.days()),

-- Periodic rotation reminders
SELECT key_path, created_at
FROM secrets
WHERE updated_at < NOW() - INTERVAL '90 days'
  AND expires_at IS NULL;
```

## Monitoring & Alerts

### Metrics
- `secrets_accessed_total` - Counter by key_path
- `secrets_access_denied_total` - Failed access attempts
- `secrets_rotation_age_days` - How old secrets are

### Alerts
- Secret accessed by unauthorized module
- Secret not rotated in 90+ days
- High volume of failed access attempts (potential breach)
- Master key environment variable missing on startup

## Migration Path

### Phase 1: Basic Encryption (MVP)
- ✅ Envelope encryption with AES-256-GCM
- ✅ Master key from environment variable
- ✅ Access control by module ID
- ✅ Audit logging

### Phase 2: Enhanced Security
- Add HMAC signature verification for webhook secrets
- IP allowlisting
- Secret versioning (keep history)
- Automatic rotation workflows

### Phase 3: Enterprise Features
- Integration with external secrets managers (Vault, AWS)
- HSM support for master key
- Multi-tenancy (org-level secrets)
- Compliance reporting (SOC2, HIPAA)

## Testing Strategy

```rust
#[tokio::test]
async fn test_secret_encryption_roundtrip() {
    let manager = SecretsManager::new(test_db_pool()).await;

    let original = "super-secret-api-key-12345";
    let secret_id = manager
        .create_secret("test/api-key", original, test_user_id(), vec![])
        .await
        .unwrap();

    let retrieved = manager
        .get_secret("test/api-key", SecretRequestor::System)
        .await
        .unwrap();

    assert_eq!(original, retrieved);
}

#[tokio::test]
async fn test_unauthorized_module_access() {
    let manager = SecretsManager::new(test_db_pool()).await;

    // Create secret allowed only for module A
    let secret_id = manager
        .create_secret("test/secret", "value", user_id(), vec![module_a_id()])
        .await
        .unwrap();

    // Module B tries to access
    let result = manager
        .get_secret("test/secret", SecretRequestor::Module(module_b_id()))
        .await;

    assert!(result.is_err());

    // Check audit log shows failed attempt
    let audit = manager.get_audit_log(secret_id).await.unwrap();
    assert_eq!(audit.last().unwrap().success, false);
}
```
