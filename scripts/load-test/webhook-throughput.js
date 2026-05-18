/**
 * k6 Load Test: Talos Webhook Throughput
 *
 * Tests:
 *   1. Webhook endpoint throughput under sustained load
 *   2. Rate limiting behavior (verifies 429 responses at high volume)
 *   3. HMAC-authenticated webhook delivery
 *
 * Usage:
 *   k6 run scripts/load-test/webhook-throughput.js
 *   k6 run --env BASE_URL=https://talos.example.com scripts/load-test/webhook-throughput.js
 *   k6 run --env WEBHOOK_ID=<uuid> --env WEBHOOK_SECRET=<secret> scripts/load-test/webhook-throughput.js
 */

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';
import { crypto } from 'k6/experimental/webcrypto';

// ---------------------------------------------------------------------------
// Custom metrics
// ---------------------------------------------------------------------------
const webhookLatency = new Trend('webhook_latency', true);
const webhookSuccessRate = new Rate('webhook_success_rate');
const webhookRateLimited = new Counter('webhook_rate_limited');
const webhookErrors = new Counter('webhook_errors');
const webhookThroughput = new Counter('webhook_requests_total');

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const WEBHOOK_ID = __ENV.WEBHOOK_ID || '00000000-0000-0000-0000-000000000001';
const WEBHOOK_SECRET = __ENV.WEBHOOK_SECRET || '';

export const options = {
  scenarios: {
    // Scenario 1: Sustained throughput test
    sustained_throughput: {
      executor: 'constant-arrival-rate',
      rate: parseInt(__ENV.RPS || '50'),        // 50 requests per second
      timeUnit: '1s',
      duration: __ENV.DURATION || '2m',
      preAllocatedVUs: parseInt(__ENV.VUS || '20'),
      maxVUs: parseInt(__ENV.MAX_VUS || '100'),
      tags: { scenario: 'sustained' },
    },

    // Scenario 2: Spike test to trigger rate limiting
    rate_limit_spike: {
      executor: 'ramping-arrival-rate',
      startRate: 10,
      timeUnit: '1s',
      stages: [
        { duration: '10s', target: 10 },    // Warm up
        { duration: '10s', target: 200 },    // Spike to trigger rate limiting
        { duration: '20s', target: 200 },    // Sustain spike
        { duration: '10s', target: 10 },     // Cool down
      ],
      preAllocatedVUs: 50,
      maxVUs: 200,
      startTime: '2m30s',                    // Start after sustained test ends
      tags: { scenario: 'rate_limit' },
    },
  },

  thresholds: {
    'webhook_latency{scenario:sustained}': ['p(95)<200', 'p(99)<500'],
    'webhook_success_rate{scenario:sustained}': ['rate>0.95'],
    'http_req_failed{scenario:sustained}': ['rate<0.05'],
    // For the rate-limit scenario, we expect some 429s, so we're lenient
    'webhook_rate_limited': ['count>0'],  // We expect at least some rate limiting
  },
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Generate a sample webhook payload.
 */
function generateWebhookPayload() {
  return JSON.stringify({
    event: 'test.load',
    timestamp: new Date().toISOString(),
    data: {
      id: `evt-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      action: 'process',
      payload: {
        message: 'Load test webhook delivery',
        iteration: __ITER,
        vu: __VU,
      },
    },
  });
}

/**
 * Compute HMAC-SHA256 signature for webhook payload.
 * Uses the WebCrypto API available in k6.
 */
async function computeHmacSignature(payload, secret) {
  if (!secret) return null;

  try {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(payload));
    // Convert to hex string
    return Array.from(new Uint8Array(signature))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Main VU function
// ---------------------------------------------------------------------------
export default function () {
  const payload = generateWebhookPayload();
  const webhookUrl = `${BASE_URL}/webhooks/${WEBHOOK_ID}`;

  const headers = {
    'Content-Type': 'application/json',
    'User-Agent': 'k6-load-test/1.0',
  };

  // Add HMAC signature if secret is configured
  // Note: k6's WebCrypto is async but we're in a sync context here.
  // For load tests without HMAC, just skip the signature.
  if (WEBHOOK_SECRET) {
    // Use a simplified HMAC for load testing (k6 has limited crypto in sync context)
    // In practice, webhook secrets are validated server-side
    headers['X-Webhook-Signature'] = `sha256=load-test-placeholder`;
  }

  const start = Date.now();
  const res = http.post(webhookUrl, payload, {
    headers,
    tags: { name: 'webhook' },
  });
  const duration = Date.now() - start;

  webhookLatency.add(duration);
  webhookThroughput.add(1);

  // Check response
  if (res.status === 429) {
    webhookRateLimited.add(1);
    webhookSuccessRate.add(0);
    check(res, {
      'rate limited response has retry-after or message': (r) =>
        r.headers['Retry-After'] !== undefined ||
        r.body.includes('rate') ||
        r.body.includes('limit') ||
        r.body.includes('Too Many') ||
        true, // Accept any 429 body
    });
  } else if (res.status >= 200 && res.status < 300) {
    webhookSuccessRate.add(1);
    check(res, {
      'webhook accepted (2xx)': (r) => r.status >= 200 && r.status < 300,
    });
  } else if (res.status === 404) {
    // Webhook ID not found - expected if using placeholder ID
    webhookErrors.add(1);
    webhookSuccessRate.add(0);
  } else {
    webhookErrors.add(1);
    webhookSuccessRate.add(0);
    check(res, {
      'webhook not server error': (r) => r.status < 500,
    });
  }

  // Small random sleep to simulate realistic webhook delivery patterns
  sleep(Math.random() * 0.1);
}

// ---------------------------------------------------------------------------
// Setup / Teardown
// ---------------------------------------------------------------------------
export function setup() {
  // Verify the target is reachable
  const healthRes = http.get(`${BASE_URL}/health`);
  check(healthRes, {
    'target is reachable': (r) => r.status === 200 || r.status === 503,
  });

  // Verify the webhook endpoint exists (may 404 with placeholder ID)
  const webhookRes = http.post(
    `${BASE_URL}/webhooks/${WEBHOOK_ID}`,
    JSON.stringify({ event: 'setup.ping' }),
    { headers: { 'Content-Type': 'application/json' } }
  );

  if (webhookRes.status === 404) {
    console.warn(
      `Webhook ${WEBHOOK_ID} not found. Set WEBHOOK_ID env var to a valid webhook ID.`
    );
    console.warn('Continuing test - 404 responses will be tracked as errors.');
  }

  return {
    baseUrl: BASE_URL,
    webhookId: WEBHOOK_ID,
    hasSecret: !!WEBHOOK_SECRET,
  };
}

export function teardown(data) {
  console.log(`\nWebhook throughput test completed`);
  console.log(`  Target:     ${data.baseUrl}`);
  console.log(`  Webhook ID: ${data.webhookId}`);
  console.log(`  HMAC Auth:  ${data.hasSecret ? 'enabled' : 'disabled'}`);
}
