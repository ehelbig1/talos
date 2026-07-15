# Google Cloud push-notification setup

Talos's Google Cloud integration can receive **Cloud Monitoring
incident** notifications in real time via Google Cloud Pub/Sub. When a
Monitoring alert policy fires, the incident is delivered to Talos within
seconds and dispatched to the WASM module bound to your watch channel.

Unlike the Gmail integration (where Talos owns one shared topic and
renews the watch every 7 days), **you own the Pub/Sub topic and
subscription** here. Nothing on the Talos side expires — the watch row
carries no TTL, and there is no renewal loop. To tear a watch down you
delete the subscription on your side and stop the watch in Talos.

This doc is the **operator runbook**: everything Talos can't do for
itself because it involves your GCP project.

> **Phase C shortcut — self-serve provisioning.** Most of the `gcloud`
> commands below (create topic, create push subscription, create the
> Monitoring notification channel — steps 1, 4, 5) can now be run as a
> Talos workflow instead, using the write-tier provisioning modules:
> `GCP: Create Pub/Sub Topic`, `GCP: Create Push Subscription`,
> `GCP: Create Monitoring Channel`. Prerequisites for that path:
>
> 1. Connect the **provisioning (write) tier** in Settings →
>    Integrations → Google Cloud → *Enable provisioning* (backed by
>    `GET /api/gcp/connect-write`). This is a SEPARATE OAuth consent
>    from the read-only connection, scoped to
>    `https://www.googleapis.com/auth/pubsub` +
>    `https://www.googleapis.com/auth/monitoring` — deliberately NOT
>    `cloud-platform`, so the stored token cannot touch Compute, IAM,
>    Storage, or anything else even if a workflow misbehaves. Its vault
>    namespace (`oauth/google_cloud_write/…`) is distinct from the
>    read tier's, so read-only modules can never resolve it.
> 2. Steps **2** (service account — a one-time IAM operation) and **3**
>    (create the watch in Talos) remain as below; IAM writes are out of
>    the write tier's scope on purpose.
> 3. Bind the provisioning workflow to an actor with
>    `max_write_ceiling = 'write'` — the worker refuses non-GET HTTP
>    for read-only actors when write-ceiling enforcement is on. Add a
>    Human-Approval-Gate node upstream if you want per-run sign-off.
>
> The modules are idempotent: re-running reports `already_existed:
> true` instead of failing (the Monitoring channel module pre-checks by
> topic label because its POST is not idempotent upstream).

## Architecture

```
Cloud Monitoring ─ alert fires ─▶ notification channel (Pub/Sub)
                                          │
                                    Pub/Sub topic (you own)
                                          │ push (HTTPS, signed JWT)
                                          ▼
                        $BASE_URL/api/gcp/pubsub/{watch_token}
                                          │
                                          ▼
                              Talos controller
                                • verifies Google-signed JWT
                                  (audience + per-watch service account)
                                • resolves the watch by {watch_token}
                                • dispatches the incident to the module
```

The per-watch **push token** in the URL path is minted by Talos when you
create the watch (shown once, and re-copyable from the watch row). It is
the secret that binds a push to its watch; the Google-signed JWT is the
authenticator.

## Prerequisites

- A GCP project you control (free tier is fine for personal use).
- `gcloud` authenticated as a principal with `pubsub.admin` +
  `monitoring.admin` in that project.
- These APIs enabled in the project:
  ```bash
  gcloud services enable \
    cloudresourcemanager.googleapis.com \
    monitoring.googleapis.com \
    pubsub.googleapis.com \
    --project=$GCP_PROJECT
  ```
- The Google Cloud integration connected in Talos with the
  **`https://www.googleapis.com/auth/cloud-platform.read-only`** scope
  (this is what the OAuth consent screen grants; the read-only probe and
  any module callbacks use it).
- Talos's public base URL (`FRONTEND_URL`) already set to a public HTTPS
  URL (ngrok in dev, your real domain in prod). Pub/Sub push requires
  HTTPS.

## Talos environment

Only **one** env var enables the GCP push receiver:

```bash
# The audience Talos checks against each push JWT's `aud` claim. Set it
# to a stable value you'll also pass to `--push-auth-token-audience`
# below. Using the push base URL is conventional.
GCP_PUBSUB_AUDIENCE=https://your.domain/api/gcp/pubsub
```

The OAuth client vars from Phase A must already be set:

```bash
GOOGLE_CLOUD_CLIENT_ID=...
GOOGLE_CLOUD_CLIENT_SECRET=...
GOOGLE_CLOUD_REDIRECT_URI=https://your.domain/api/gcp/callback
```

Restart the controller and look for:

```
INFO Google Cloud push service enabled
```

(If `GCP_PUBSUB_AUDIENCE` is unset you'll instead see
`Google Cloud push service disabled (set GCP_PUBSUB_AUDIENCE to enable)`
and the watch-channel routes won't be wired.)

## Step-by-step (per user)

Variables used below (substitute your values):

```bash
export GCP_PROJECT=my-project-id
export TOPIC=talos-monitoring-alerts
export SUBSCRIPTION=talos-monitoring-sub
export GCP_PUBSUB_AUDIENCE=https://your.domain/api/gcp/pubsub
```

### 1. Create the topic

```bash
gcloud pubsub topics create $TOPIC --project=$GCP_PROJECT
```

### 2. Create a service account for push auth

Pub/Sub signs each push with a JWT using this account. Talos verifies
the signature is from Google AND that the token's `email` matches the
`expected_sa_email` you set on the watch.

```bash
gcloud iam service-accounts create talos-gcp-pusher \
  --display-name="Talos Pub/Sub push identity" \
  --project=$GCP_PROJECT

export SA_EMAIL=talos-gcp-pusher@$GCP_PROJECT.iam.gserviceaccount.com
```

Grant it permission to mint push-auth tokens:

```bash
gcloud projects add-iam-policy-binding $GCP_PROJECT \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/iam.serviceAccountTokenCreator"
```

### 3. Create the watch in Talos (copy the push endpoint)

1. Open Talos Settings → Integrations → Google Cloud → **Connect** (if
   not already connected).
2. Scroll to the **Google Cloud Watch Channels** panel → **Create**.
3. Fill in:
   - **Google Cloud account** — the connected integration.
   - **Push service-account email** — `$SA_EMAIL` from step 2.
   - **Display name** — e.g. `Prod alerting` (optional).
   - **Module ID** — the WASM module to run on each incident (optional;
     you can bind it later in the workflow builder).
4. On success Talos shows the **push endpoint** exactly once:
   `https://your.domain/api/gcp/pubsub/<token>`. Copy it. (You can
   re-copy it later from the watch row's **Endpoint** button.)

```bash
export PUSH_ENDPOINT="<paste the copied endpoint here>"
```

### 4. Create the push subscription

```bash
gcloud pubsub subscriptions create $SUBSCRIPTION \
  --project=$GCP_PROJECT \
  --topic=$TOPIC \
  --push-endpoint="$PUSH_ENDPOINT" \
  --push-auth-service-account=$SA_EMAIL \
  --push-auth-token-audience="$GCP_PUBSUB_AUDIENCE" \
  --ack-deadline=60
```

`--push-auth-token-audience` MUST equal Talos's `GCP_PUBSUB_AUDIENCE`
exactly — Talos checks it against the JWT `aud` claim before any DB
work. `--push-auth-service-account` MUST equal the watch's
`expected_sa_email`, checked per-watch after the token is resolved.

### 5. Create a Monitoring notification channel + attach it to a policy

```bash
gcloud beta monitoring channels create \
  --project=$GCP_PROJECT \
  --type=pubsub \
  --display-name="Talos incidents" \
  --channel-labels=topic=projects/$GCP_PROJECT/topics/$TOPIC

# Note the returned channel id, then attach it to an alerting policy
# (either in the console, or via `gcloud alpha monitoring policies
# update <POLICY_ID> --add-notification-channels=<CHANNEL_ID>`).
```

Cloud Monitoring publishes to the topic as a Google-managed service
account (`service-<project-number>@gcp-sa-monitoring-notification.iam.gserviceaccount.com`),
which Pub/Sub authorizes automatically for the channel.

### 6. Verify end-to-end

Publish a synthetic incident envelope to the topic and watch the
controller logs:

```bash
gcloud pubsub topics publish $TOPIC --project=$GCP_PROJECT \
  --message '{"version":"1.2","incident":{"incident_id":"test-1","state":"open","policy_name":"synthetic"}}'
```

Within seconds you should see `gcp job published to worker` (if a module
is bound) or `gcp dispatch: no module bound` in the controller logs, and
the watch row's **Last push** column should update.

> Note: a `gcloud pubsub topics publish` message is NOT signed by your
> push service account, so it arrives WITHOUT the required auth JWT and
> Talos will reject it with 401 at the push endpoint. To exercise the
> full path, trigger the real alert policy (or temporarily lower a
> threshold) so Cloud Monitoring delivers a properly-signed push.

If nothing arrives:

- Check the subscription's "undelivered message" / "push errors"
  metrics in the GCP console. Non-zero = Pub/Sub is trying but getting
  rejected (usually an audience or service-account mismatch → 401).
- Confirm `$BASE_URL` is publicly reachable (`curl $BASE_URL/health`
  from outside your network).
- Confirm `--push-auth-token-audience` matches `GCP_PUBSUB_AUDIENCE`
  and `--push-auth-service-account` matches the watch's SA email
  exactly.

## Teardown

```bash
gcloud pubsub subscriptions delete $SUBSCRIPTION --project=$GCP_PROJECT
gcloud pubsub topics delete $TOPIC --project=$GCP_PROJECT
gcloud iam service-accounts delete $SA_EMAIL --project=$GCP_PROJECT
```

Then **Stop** the watch in the Talos UI (or
`POST /api/admin/gcp/stop-all`). Because Talos never created an upstream
resource, deleting the subscription + stopping the watch is the whole
cleanup — there is no renewal loop and no orphan to expire.

## Cost expectations

Cloud Monitoring push volume scales with your incident rate, not with
polling. At personal / small-team scale (a handful of incidents per day)
you're well inside the Pub/Sub free tier (10 GiB/mo ingress). Each
incident envelope is a few KiB (documentation + policy + condition
text); Talos caps the push body at 256 KiB.
