# Gmail Integration Guide

This guide explains how to set up and use Gmail OAuth integration to populate node configuration forms with real Gmail data.

## Overview

The Gmail integration allows users to:
- Connect their Gmail accounts via OAuth 2.0
- Fetch real Gmail labels to populate dropdown menus
- Automatically refresh access tokens when they expire
- Manage multiple Gmail account connections

This is similar to the Slack integration but specifically for Gmail/Google Workspace accounts.

## Setup Instructions

### 1. Create Google Cloud Project

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the **Gmail API**:
   - Navigate to "APIs & Services" → "Library"
   - Search for "Gmail API"
   - Click "Enable"

### 2. Create OAuth 2.0 Credentials

1. Go to "APIs & Services" → "Credentials"
2. Click "Create Credentials" → "OAuth client ID"
3. Select "Web application"
4. Configure:
   - **Name**: Talos Gmail Integration
   - **Authorized JavaScript origins**: `http://localhost:3000` (for development)
   - **Authorized redirect URIs**: `http://localhost:8000/api/gmail/callback`
5. Click "Create"
6. Copy the **Client ID** and **Client Secret**

### 3. Configure Environment Variables

Add these to your `.env` file:

```bash
# Gmail Integration
GMAIL_CLIENT_ID=your-gmail-client-id.apps.googleusercontent.com
GMAIL_CLIENT_SECRET=your-gmail-client-secret
GMAIL_REDIRECT_URI=http://localhost:8000/api/gmail/callback
```

### 4. Run Database Migrations

```bash
sqlx migrate run
```

This will create the `gmail_integrations` and `gmail_integration_audit_log` tables.

### 5. Restart the Controller

```bash
cd controller
cargo run
```

You should see:
```
Gmail integration service initialized
Gmail API client initialized
```

## API Endpoints

### Integration Management

#### Connect Gmail Account
```
GET /api/gmail/connect
```

Returns an OAuth authorization URL that the user should visit to grant permissions.

**Response:**
```json
{
  "success": true,
  "data": {
    "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth?...",
    "csrf_token": "random-token"
  }
}
```

#### OAuth Callback
```
GET /api/gmail/callback?code=...&state=...
```

Handles the OAuth callback after user grants permissions. Automatically exchanges the code for access and refresh tokens.

#### List Connected Accounts
```
GET /api/gmail/integrations
```

Returns all Gmail accounts connected by the authenticated user.

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": "uuid",
      "email_address": "user@gmail.com",
      "account_name": "John Doe",
      "scope": "gmail.readonly,gmail.modify,userinfo.email",
      "is_active": true,
      "created_at": "2024-01-01T00:00:00Z",
      "last_used_at": "2024-01-01T12:00:00Z",
      "token_expires_at": "2024-01-01T13:00:00Z"
    }
  ]
}
```

#### Get Integration Details
```
GET /api/gmail/integrations/{id}
```

Returns details for a specific integration.

#### Disconnect Account
```
DELETE /api/gmail/integrations/{id}
```

Deactivates a Gmail integration.

### Gmail API Proxies

These endpoints use the stored access tokens to fetch Gmail data.

#### List Labels
```
GET /api/gmail/labels?access_token=...
```

Fetches all labels from the user's Gmail account.

**Response:**
```json
{
  "ok": true,
  "data": {
    "labels": [
      {
        "id": "INBOX",
        "name": "INBOX",
        "type": "system"
      },
      {
        "id": "Label_123",
        "name": "Important",
        "type": "user"
      }
    ]
  }
}
```

#### Get Profile
```
GET /api/gmail/profile?access_token=...
```

Fetches the user's Gmail profile information.

## Frontend Integration Example

```typescript
// 1. Initiate OAuth flow
const connectGmail = async () => {
  const response = await fetch('/api/gmail/connect', {
    headers: {
      'Authorization': `Bearer ${accessToken}`
    }
  });
  const { data } = await response.json();

  // Redirect user to Google OAuth
  window.location.href = data.authorization_url;
};

// 2. After OAuth callback, list connected accounts
const fetchGmailAccounts = async () => {
  const response = await fetch('/api/gmail/integrations', {
    headers: {
      'Authorization': `Bearer ${accessToken}`
    }
  });
  const { data } = await response.json();
  return data; // Array of connected Gmail accounts
};

// 3. Fetch labels for a connected account
const fetchGmailLabels = async (integrationId: string) => {
  // First get the integration to get the access token
  const integration = await fetch(`/api/gmail/integrations/${integrationId}`, {
    headers: {
      'Authorization': `Bearer ${accessToken}`
    }
  }).then(r => r.json());

  // Then use the access token to fetch labels
  const labels = await fetch(
    `/api/gmail/labels?access_token=${integration.data.access_token}`,
    {
      headers: {
        'Authorization': `Bearer ${accessToken}`
      }
    }
  ).then(r => r.json());

  return labels.data.labels;
};

// 4. Use labels to populate a form dropdown
const labelOptions = labels.map(label => ({
  value: label.id,
  label: label.name
}));
```

## Node Template Usage

The Gmail Mail Webhook node template can be configured with real labels from the user's account:

```typescript
// In your node configuration form
const GmailWebhookConfig = () => {
  const [labels, setLabels] = useState([]);
  const [selectedLabels, setSelectedLabels] = useState(['INBOX']);

  useEffect(() => {
    // Fetch labels when component mounts
    fetchGmailLabels(integrationId).then(setLabels);
  }, [integrationId]);

  return (
    <div>
      <label>Watch Labels</label>
      <MultiSelect
        options={labels}
        value={selectedLabels}
        onChange={setSelectedLabels}
      />
    </div>
  );
};
```

## Token Refresh

Access tokens expire after 1 hour. The `GmailIntegrationService` automatically handles token refresh using the refresh token when:

- A token is expired or expires within 5 minutes
- The `get_integration_with_token()` method is called

```rust
// Automatically refreshes if needed
let integration = service
    .get_integration_with_token(integration_id, user_id)
    .await?;

// Now you can safely use integration.access_token
```

## Security Considerations

1. **Access tokens are stored encrypted** in the database using the `TALOS_MASTER_KEY`
2. **Refresh tokens are stored encrypted** to allow automatic token renewal
3. **OAuth scopes are minimal**:
   - `gmail.readonly` - Read emails and settings
   - `gmail.modify` - Modify labels and read/write access
   - `userinfo.email` - Get user's email address
4. **Rate limiting** applies to all Gmail API endpoints
5. **Authentication required** - All endpoints require valid JWT token
6. **Audit logging** tracks all integration events (connect, disconnect, token refresh)

## Troubleshooting

### "Gmail OAuth is not configured on this server"

Make sure you've set the environment variables:
- `GMAIL_CLIENT_ID`
- `GMAIL_CLIENT_SECRET`
- `GMAIL_REDIRECT_URI`

### "Invalid grant" error during OAuth

This usually means:
- The authorization code has already been used
- The authorization code has expired (they expire in 10 minutes)
- The redirect URI doesn't match what's configured in Google Cloud Console

### Token refresh fails

Check that:
- The refresh token is still valid (Google can revoke them)
- The user hasn't revoked access in their Google Account settings
- The OAuth client credentials are still valid

## Production Deployment

For production:

1. Update redirect URI to your production domain:
   ```bash
   GMAIL_REDIRECT_URI=https://yourdomain.com/api/gmail/callback
   ```

2. Add the redirect URI to Google Cloud Console OAuth client configuration

3. Consider adding domain verification for better user trust:
   - Go to Google Cloud Console → "APIs & Services" → "OAuth consent screen"
   - Add your domain and verify ownership

4. Request verification from Google if your app will be used by external users:
   - Go to "OAuth consent screen"
   - Click "Publish app"
   - Submit for verification

## Related Files

- **Migration**: `/migrations/006_gmail_integrations.sql`
- **Service**: `/controller/src/gmail/integration.rs`
- **API Client**: `/controller/src/gmail/mod.rs`
- **Handlers**: `/controller/src/gmail/handlers.rs`
- **Node Template**: `/templates/google-mail-webhook/`
