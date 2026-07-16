# Google Cloud impersonation setup (Phase D)

Talos's Google Cloud integration can let a workflow act as a Google Cloud
**service account** — for example to deploy a Cloud Run revision or read
Cloud Logging — **without ever storing a service-account key**. Instead,
the controller mints a short-lived *impersonated* token at dispatch time
and hands the workflow module only that token.

This doc is the **operator runbook** for the impersonation (full) tier:
the one-time Google Cloud setup Talos can't do for itself, plus how to
wire a workflow to use it safely.

> If you only need to receive Cloud Monitoring alerts, or to provision
> Pub/Sub topics and subscriptions, you do **not** need this tier — see
> [`docs/gcp-push-setup.md`](./gcp-push-setup.md) (read + write/provisioning
> tiers). The impersonation tier is strictly for workflows that must *act
> as* a GCP service account.

## Security model

The full-tier consent is the **broadest** Google Cloud grant Talos asks
for: a `cloud-platform` OAuth token. That token is **host-reserved** — it
lives only in controller memory (same protection class as LLM provider
keys; see `is_controller_internal_vault_path` in
`talos-workflow-job-protocol`) and is **never** placed on the wire to a
worker or handed to a workflow module. Its sole use is as the bearer for a
call to Google's IAM Credentials API
(`iamcredentials.generateAccessToken`), which returns a **short-lived
(~10 minute) impersonated token scoped to ONE service account** and
bounded by that service account's own IAM roles. A workflow module names
the minted token via the vault path
`vault://gcp/impersonated/<sa_email>/access_token` and must carry a
`gcp/impersonated/*` entry in its `allowed_secrets` grant; the controller
resolves that path by minting on demand (see
`talos-google-cloud/src/impersonation.rs`). Google itself enforces the
gate: the mint only succeeds if the consenting user holds
`roles/iam.serviceAccountTokenCreator` on `<sa_email>`, so a workflow can
only ever impersonate service accounts the user was explicitly granted
that role on — and never the broad token itself.

> **Strong recommendation: use a dedicated, low-value sandbox GCP
> project.** Even though the minted token is scoped to one service account
> and expires in ~10 minutes, the cleanest blast-radius bound is to make
> that one service account live in a throwaway project with nothing
> valuable in it. Do **not** grant impersonation against a service account
> in your production project as a first step. The runbook below assumes a
> dedicated `$SANDBOX` project.

## Prerequisites

- `gcloud` authenticated as a user with permission to create service
  accounts and set IAM policy in the sandbox project.
- The **email address of the Google identity you will connect to Talos**
  as the full tier (this is the identity Google checks for
  `serviceAccountTokenCreator`). Referred to below as `$CONSENT_USER`
  (e.g. `you@example.com`).

```bash
export SANDBOX="my-talos-sandbox"          # a DEDICATED, low-value project
export CONSENT_USER="you@example.com"      # the Google identity you connect to Talos
export RUNNER_SA="talos-runner@${SANDBOX}.iam.gserviceaccount.com"
```

## Step 1 — Create/choose the sandbox project and enable APIs

Use a project that holds nothing you'd mind a leaked 10-minute token
touching.

```bash
# Create it (skip if you're reusing an existing throwaway project):
gcloud projects create "$SANDBOX"

# Enable only what the runner needs:
gcloud services enable \
  run.googleapis.com \
  iamcredentials.googleapis.com \
  logging.googleapis.com \
  --project="$SANDBOX"
```

`iamcredentials.googleapis.com` is the API the controller calls to mint
the impersonated token — it must be enabled or every mint fails with a
403/SERVICE_DISABLED.

## Step 2 — Create the runner service account

This is the identity your workflow will *become*. Give it a clear,
purpose-specific name.

```bash
gcloud iam service-accounts create talos-runner \
  --project="$SANDBOX" \
  --display-name="Talos workflow runner (sandbox)"
```

## Step 3 — Grant the runner SA only what it needs (least privilege)

The minted token's effective power is the **intersection** of the
`cloud-platform` mint scope and the runner SA's own IAM roles — so the SA's
roles are the real ceiling. Grant the minimum for your workflow. For a
Cloud Run deploy + log read:

```bash
gcloud projects add-iam-policy-binding "$SANDBOX" \
  --member="serviceAccount:${RUNNER_SA}" \
  --role="roles/run.developer"

gcloud projects add-iam-policy-binding "$SANDBOX" \
  --member="serviceAccount:${RUNNER_SA}" \
  --role="roles/logging.viewer"
```

> **Do NOT grant the runner SA `roles/owner` or `roles/editor`.** Those are
> broad, mutating roles — a leaked minted token would inherit all of it for
> its ~10-minute life. Grant only the specific `roles/*.developer` /
> `roles/*.viewer` roles the workflow actually needs, and add more
> narrowly as requirements grow.

## Step 4 — Let the consenting user impersonate ONLY this SA

This is the gate that makes the full-tier token useful **and** bounded.
Grant `$CONSENT_USER` the token-creator role **on the runner SA resource**
(not on the project):

```bash
gcloud iam service-accounts add-iam-policy-binding "$RUNNER_SA" \
  --project="$SANDBOX" \
  --member="user:${CONSENT_USER}" \
  --role="roles/iam.serviceAccountTokenCreator"
```

Because this binding is on the **service-account resource**, Google
enforces it **per-SA**: `$CONSENT_USER`'s full-tier token can mint
impersonated tokens for `talos-runner` and **nothing else**. To let a
workflow impersonate a second SA, you must repeat this binding on that SA
— there is no project-wide shortcut, and that is the point. Never grant
`serviceAccountTokenCreator` at the project level; that would let the
token impersonate every SA in the project.

## Step 5 — Connect the full tier in Talos

In the Talos UI: **Settings → Integrations → Google Cloud → Enable
impersonation** (the red/destructive action on the Google Cloud card,
backed by `GET /api/gcp/connect-full`). Complete the Google consent
screen — this is a **broad `cloud-platform` consent**, distinct from the
read and provisioning consents, and is deliberately styled as the
highest-privilege grant. Sign in as **`$CONSENT_USER`** (the identity you
granted `serviceAccountTokenCreator` to in Step 4).

After connecting, the Google Cloud watch-channel panel's *Connected
accounts* row shows the account with an **Impersonation** badge, alongside
any read/provisioning rows for the same account.

## Step 6 — Wire a workflow to impersonate the runner SA

In the workflow builder:

1. **Bind an actor with a `write` write-ceiling** to the workflow — the
   worker refuses non-GET HTTP for read-only actors when write-ceiling
   enforcement is on, and impersonated calls to Cloud Run/etc. are
   mutating.
2. On the HTTP-node module, set the outbound auth header to reference the
   minted token by vault path:

   ```
   AUTH_HEADER = Bearer vault://gcp/impersonated/talos-runner@my-talos-sandbox.iam.gserviceaccount.com/access_token
   ```

   (substitute your real `$RUNNER_SA`). The controller resolves this path
   by minting a fresh ~10-minute token per dispatch.
3. Grant the module `allowed_secrets: ["gcp/impersonated/*"]` so it is
   permitted to resolve the minted-token path — nothing else in the
   `gcp/*` namespace is exposed to it, and the broad `google_cloud_full`
   token is host-reserved and unreachable regardless of this grant.
4. **Put a Human-Approval-Gate node before any destructive step** (deploy,
   delete, IAM change). Impersonation runs with real SA authority; a
   sign-off gate gives you a per-run checkpoint.

## Blast radius summary

| If this leaks…                              | Runs as        | Lifetime   | Scope                                              | How it's bounded |
|---------------------------------------------|----------------|------------|----------------------------------------------------|------------------|
| A **minted impersonated token** (the one a workflow module holds) | one SA (`talos-runner`) | ~10 minutes | the runner SA's IAM roles, in the **sandbox** project only | short TTL + least-privilege SA roles + dedicated throwaway project |
| The **broad `cloud-platform` token** (full-tier consent) | *n/a — it never leaves the controller* | — | — | **host-reserved**: kept only in controller memory, never placed on the wire to a worker and never handed to a workflow module (same class as LLM provider keys) |

The design goal: the token a workflow can actually touch is the weak,
short-lived, single-SA one; the powerful token is structurally
unreachable by workflow code.

## Teardown

Reverse the grants when you're done, most-privileged first:

```bash
# 1. Revoke the user's ability to impersonate the runner SA.
gcloud iam service-accounts remove-iam-policy-binding "$RUNNER_SA" \
  --project="$SANDBOX" \
  --member="user:${CONSENT_USER}" \
  --role="roles/iam.serviceAccountTokenCreator"

# 2. Delete the runner SA (also drops its project role bindings).
gcloud iam service-accounts delete "$RUNNER_SA" --project="$SANDBOX"
```

3. In Talos: **Settings → Integrations → Google Cloud → Connected
   accounts**, disconnect the **Impersonation** row. This revokes the
   `cloud-platform` consent at Google, so the host-reserved token can no
   longer be refreshed or used to mint.

Once Step 1 (revoke `serviceAccountTokenCreator`) is done, no token — even
one already minted — can be re-minted, and Google will reject impersonation
attempts against the runner SA. Deleting the sandbox project entirely is
the strongest teardown if the project was created solely for this purpose.
