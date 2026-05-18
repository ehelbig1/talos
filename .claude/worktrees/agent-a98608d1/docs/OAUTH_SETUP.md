# OAuth & OIDC Setup Guide

This guide explains how to configure Google OAuth 2.0 and Okta OIDC for Talos authentication.

## 🎯 Overview

Talos supports OAuth 2.0 and OpenID Connect (OIDC) authentication with:
- **Google** - Social login for consumer accounts
- **Okta** - Enterprise SSO for organizations

## 📋 Prerequisites

- Talos instance running
- Admin access to Google Cloud Console (for Google OAuth)
- Admin access to Okta Dashboard (for Okta OIDC)

---

## 🔵 Google OAuth 2.0 Setup

### Step 1: Create a Google Cloud Project

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the **Google+ API** (for profile information)

### Step 2: Configure OAuth Consent Screen

1. Navigate to **APIs & Services** → **OAuth consent screen**
2. Choose **External** (for public access) or **Internal** (for organization only)
3. Fill in required fields:
   - **App name**: `Talos`
   - **User support email**: Your email
   - **Developer contact email**: Your email
4. Add scopes:
   - `openid`
   - `email`
   - `profile`
5. Save and continue

### Step 3: Create OAuth Credentials

1. Navigate to **APIs & Services** → **Credentials**
2. Click **+ CREATE CREDENTIALS** → **OAuth 2.0 Client ID**
3. Select **Web application**
4. Configure:
   - **Name**: `Talos OAuth Client`
   - **Authorized JavaScript origins**:
     ```
     http://localhost:8000
     https://your-domain.com
     ```
   - **Authorized redirect URIs**:
     ```
     http://localhost:8000/auth/oauth/google/callback
     https://your-domain.com/auth/oauth/google/callback
     ```
5. Click **CREATE**
6. Copy the **Client ID** and **Client Secret**

### Step 4: Configure Talos Environment

Add to `.env`:

```bash
GOOGLE_CLIENT_ID=123456789-abcdefg.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-your-secret-here
GOOGLE_REDIRECT_URI=http://localhost:8000/auth/oauth/google/callback
```

### Step 5: Test Google Login

1. Restart Talos controller
2. Navigate to login page
3. Click "Continue with Google"
4. Verify authentication flow

---

## 🔷 Okta OIDC Setup

### Step 1: Create an Okta Application

1. Log in to your [Okta Admin Dashboard](https://login.okta.com/)
2. Navigate to **Applications** → **Applications**
3. Click **Create App Integration**
4. Select:
   - **Sign-in method**: OIDC - OpenID Connect
   - **Application type**: Web Application
5. Click **Next**

### Step 2: Configure Application Settings

Fill in the following:

- **App integration name**: `Talos`
- **Grant type**: Check **Authorization Code**
- **Sign-in redirect URIs**:
  ```
  http://localhost:8000/auth/oauth/okta/callback
  https://your-domain.com/auth/oauth/okta/callback
  ```
- **Sign-out redirect URIs**:
  ```
  http://localhost:3000
  https://your-frontend-domain.com
  ```
- **Controlled access**: Choose based on your organization's needs
  - **Allow everyone in your organization to access** (recommended for testing)
  - **Limit access to selected groups** (production)

Click **Save**.

### Step 3: Get Client Credentials

After creating the application:

1. Copy the **Client ID** (shown immediately)
2. Copy the **Client secret** (click eye icon to reveal)
3. Note your **Okta domain** (e.g., `dev-12345.okta.com`)

### Step 4: Assign Users/Groups

1. Go to **Assignments** tab
2. Click **Assign** → **Assign to People** or **Assign to Groups**
3. Add users who should have access to Talos

### Step 5: Configure Talos Environment

Add to `.env`:

```bash
OKTA_DOMAIN=dev-12345.okta.com
OKTA_CLIENT_ID=0oa1b2c3d4e5f6g7h8i9
OKTA_CLIENT_SECRET=your-okta-secret-here
OKTA_REDIRECT_URI=http://localhost:8000/auth/oauth/okta/callback
```

### Step 6: Test Okta Login

1. Restart Talos controller
2. Navigate to login page
3. Click "Continue with Okta"
4. Verify authentication flow with test user

---

## 🔐 Security Best Practices

### Required Settings

1. **HTTPS in Production**
   - Always use HTTPS redirect URIs in production
   - OAuth providers reject HTTP in production

2. **Redirect URI Whitelist**
   - Only add necessary redirect URIs
   - Never use wildcards
   - Keep separate credentials for dev/staging/prod

3. **Token Security**
   - Client secrets are sensitive - treat like passwords
   - Rotate secrets periodically
   - Never commit secrets to Git

### Recommended Settings

1. **PKCE (Proof Key for Code Exchange)**
   - Enabled by default in our implementation
   - Provides additional security for authorization code flow

2. **State Parameter**
   - CSRF protection enabled automatically
   - Validates callback authenticity

3. **Email Verification**
   - Our implementation checks `email_verified` claim
   - Unverified emails can be rejected (optional)

---

## 🧪 Testing

### Test Google OAuth

```bash
# 1. Get authorization URL
curl http://localhost:8000/auth/oauth/google/login

# Expected: Redirects to Google login page

# 2. After successful auth, check callback
# Expected: Redirect to http://localhost:3000/auth/callback?success=true
```

### Test Okta OIDC

```bash
# 1. Get authorization URL
curl http://localhost:8000/auth/oauth/okta/login

# Expected: Redirects to Okta login page

# 2. After successful auth, check callback
# Expected: Redirect to http://localhost:3000/auth/callback?success=true
```

### Test Account Linking

1. Create account with email/password
2. Log in
3. Navigate to Settings → Linked Accounts
4. Click "Connect" for Google or Okta
5. Authorize with same email
6. Verify account is linked

---

## 🐛 Troubleshooting

### Error: "Redirect URI mismatch"

**Problem**: OAuth provider rejects redirect URI

**Solution**:
- Verify redirect URI in `.env` matches OAuth provider config exactly
- Check for trailing slashes
- Ensure protocol matches (http vs https)

### Error: "Invalid client"

**Problem**: Client ID or secret incorrect

**Solution**:
- Double-check client ID and secret from provider
- Ensure no extra spaces or newlines
- Regenerate credentials if needed

### Error: "Email not verified"

**Problem**: User's email not verified with provider

**Solution**:
- Ask user to verify email with Google/Okta
- Or disable email verification check in code (not recommended)

### Error: "Failed to discover OIDC metadata"

**Problem**: Okta domain incorrect

**Solution**:
- Verify `OKTA_DOMAIN` format: `dev-12345.okta.com` (no https://)
- Check Okta domain in Admin Dashboard
- Ensure network can reach Okta discovery endpoint

### Users Can't Link Accounts

**Problem**: Email mismatch between accounts

**Solution**:
- OAuth email must match existing user email
- Check email case sensitivity
- Verify email in OAuth provider profile

---

## 🔄 Account Linking Flow

### Auto-Registration (New Users)

1. User clicks "Continue with Google/Okta"
2. User authenticates with provider
3. **If email doesn't exist**: Create new user account
4. Link OAuth account to new user
5. Redirect to dashboard

### Account Linking (Existing Users)

1. User logs in with email/password
2. Navigates to Settings → Linked Accounts
3. Clicks "Connect" for provider
4. Authenticates with provider
5. **If email matches**: Link OAuth account
6. **If email doesn't match**: Show error

### SSO Login (Linked Accounts)

1. User clicks "Continue with Google/Okta"
2. User authenticates with provider
3. System finds linked OAuth account
4. Logs user in directly
5. Redirect to dashboard

---

## 📊 GraphQL API

### Get OAuth Login URL

```graphql
query GetOAuthUrl($provider: String!) {
  oauthLoginUrl(provider: $provider) {
    authUrl
    provider
  }
}
```

### List Linked Accounts

```graphql
query GetLinkedAccounts {
  linkedOAuthAccounts {
    id
    provider
    email
    name
    pictureUrl
    linkedAt
    lastLoginAt
  }
}
```

### Unlink Account

```graphql
mutation UnlinkAccount($provider: String!) {
  unlinkOAuthAccount(provider: $provider)
}
```

---

## 🚀 Production Deployment

### Google OAuth Production Checklist

- [ ] Use production Google Cloud project
- [ ] Set OAuth consent screen to "Published" status
- [ ] Add production domain to authorized origins
- [ ] Use HTTPS redirect URIs only
- [ ] Store secrets in secure vault (not .env file)
- [ ] Enable logging and monitoring
- [ ] Test with real users

### Okta OIDC Production Checklist

- [ ] Use production Okta tenant
- [ ] Assign appropriate user groups
- [ ] Configure MFA requirements
- [ ] Use HTTPS redirect URIs only
- [ ] Store secrets in secure vault
- [ ] Enable audit logging
- [ ] Configure session policies
- [ ] Test SSO with enterprise users

---

## 📚 Additional Resources

### Google OAuth
- [Google OAuth 2.0 Documentation](https://developers.google.com/identity/protocols/oauth2)
- [OAuth Consent Screen Best Practices](https://support.google.com/cloud/answer/10311615)

### Okta OIDC
- [Okta OIDC Documentation](https://developer.okta.com/docs/guides/implement-oauth-for-okta/main/)
- [Okta Best Practices](https://developer.okta.com/docs/guides/best-practices/)

### Security
- [OWASP OAuth Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Security_Cheat_Sheet.html)
- [OpenID Connect Core Specification](https://openid.net/specs/openid-connect-core-1_0.html)

---

## 🤝 Support

If you encounter issues:
1. Check logs: `docker-compose logs controller`
2. Verify environment variables: `docker-compose exec controller env | grep OAUTH`
3. Review GitHub issues: https://github.com/your-repo/talos/issues
4. Contact support: support@example.com
