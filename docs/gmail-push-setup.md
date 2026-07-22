# Gmail push-notification setup

Talos's Gmail integration supports real-time push notifications via
Google Cloud Pub/Sub. When enabled, every mailbox change is delivered
to Talos within seconds; the watch row in `integration_state` is
automatically renewed every 7 days.

This doc is the **operator runbook**: everything Talos can't do for
itself because it involves your GCP project.

## Architecture

```
Gmail ─ publishes ─▶ Pub/Sub topic ─ push ─▶ $BASE_URL/api/gmail/pubsub
                    (you own)                    │
                                                 ▼
                                   Talos controller
                                     • verifies JWT
                                     • finds user by emailAddress
                                     • calls history.list
                                     • advances cursor
```

One shared topic for all Talos users; each push carries the user's
email so the handler routes it correctly.

## Prerequisites

- A GCP project you control (free tier is fine for personal use).
  **CRITICAL: this MUST be the same project that owns the Gmail OAuth
  client** the integration authenticates through. Gmail's `users.watch`
  rejects any topic outside that project with
  `Invalid topicName does not match projects/<oauth-project>/topics/*`.
  If you're unsure which project that is, the error message names it — put
  the topic there. (A separate "sandbox" project you use for other GCP work
  will NOT work.)
- `gcloud` authenticated as a principal with `pubsub.admin` in that
  project.
- Talos's `BASE_URL` already set to a public HTTPS URL (ngrok in dev,
  your real domain in prod). Pub/Sub push requires HTTPS.

## Step-by-step

Variables used below (substitute your values):

```bash
export GCP_PROJECT=my-project-id
export TOPIC=gmail-push
export SUBSCRIPTION=gmail-push-sub
export BASE_URL=https://your.ngrok.io              # or your production URL
export PUSH_ENDPOINT=$BASE_URL/api/gmail/pubsub
```

### 1. Create the topic

```bash
gcloud pubsub topics create $TOPIC --project=$GCP_PROJECT
```

### 2. Grant Gmail permission to publish to it

Gmail's push service publishes as
`gmail-api-push@system.gserviceaccount.com`. Grant it `publisher`:

```bash
gcloud pubsub topics add-iam-policy-binding $TOPIC \
  --project=$GCP_PROJECT \
  --member="serviceAccount:gmail-api-push@system.gserviceaccount.com" \
  --role="roles/pubsub.publisher"
```

### 3. Create a service account for push auth

Pub/Sub will sign each push with a JWT using this account as `sub`
and `email`. Talos verifies the signature is from Google AND that
the `email` matches what you configure.

```bash
gcloud iam service-accounts create talos-pubsub-pusher \
  --display-name="Talos Pub/Sub push identity" \
  --project=$GCP_PROJECT

export SA_EMAIL=talos-pubsub-pusher@$GCP_PROJECT.iam.gserviceaccount.com
```

Grant it permission to invoke the push endpoint (Pub/Sub checks this
against the subscription):

```bash
gcloud projects add-iam-policy-binding $GCP_PROJECT \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/iam.serviceAccountTokenCreator"
```

### 4. Create the push subscription

```bash
gcloud pubsub subscriptions create $SUBSCRIPTION \
  --project=$GCP_PROJECT \
  --topic=$TOPIC \
  --push-endpoint=$PUSH_ENDPOINT \
  --push-auth-service-account=$SA_EMAIL \
  --push-auth-token-audience=$PUSH_ENDPOINT \
  --ack-deadline=60
```

The `--push-auth-token-audience` is what Talos will check against
the JWT's `aud` claim. Set it to the webhook URL exactly — including
the path.

### 5. Configure Talos

Add to `.env`:

```bash
GMAIL_PUBSUB_TOPIC=projects/$GCP_PROJECT/topics/$TOPIC
GMAIL_PUBSUB_AUDIENCE=$PUSH_ENDPOINT
GMAIL_PUBSUB_SERVICE_ACCOUNT=$SA_EMAIL       # optional; default is the Gmail-system account
GMAIL_DEFAULT_LABEL_IDS=INBOX                # optional; comma-separated
```

Restart the controller:

```bash
docker compose up -d --force-recreate --no-deps controller
```

Look for this line in the logs:

```
INFO Gmail push service enabled topic=projects/…/topics/gmail-push
```

### 6. Verify end-to-end

1. Open Talos Settings → Integrations → Gmail → "Connect" (if not
   already connected).
2. Scroll to the new **Gmail Watch Channels** panel and click
   **Create your first watch channel**.
3. Send yourself an email. Within seconds you should see
   `gmail push: history page synced` in the controller logs.

If the log line never appears:

- Check the subscription's "undelivered message" metric in the GCP
  console. Non-zero = Pub/Sub is trying but getting rejected.
- Check that `BASE_URL` is publicly reachable (`curl $BASE_URL/health`
  from outside your network).
- Check that `GMAIL_PUBSUB_AUDIENCE` matches the push endpoint exactly.

## Teardown

```bash
gcloud pubsub subscriptions delete $SUBSCRIPTION --project=$GCP_PROJECT
gcloud pubsub topics delete $TOPIC --project=$GCP_PROJECT
gcloud iam service-accounts delete $SA_EMAIL --project=$GCP_PROJECT
```

Then unset the four `GMAIL_PUBSUB_*` vars in `.env` and restart Talos.
Any active watches will fail their next renewal and be removed after
TTL grace (14 days past Google's expiration).

## Cost expectations

Gmail push volume scales with your mailbox activity, not with polling
frequency. At personal scale (a few hundred mails/day) you're well
inside the Pub/Sub free tier (10 GiB/mo ingress). Each message is
under 200 bytes.
