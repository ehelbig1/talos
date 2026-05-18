/**
 * k6 Load Test: Talos Workflow Execution Pipeline
 *
 * Stress-tests the full workflow execution lifecycle:
 *   1. Sustained workflow creation and execution (constant VUs)
 *   2. Burst concurrent workflow triggers (ramping VUs)
 *   3. Health endpoint under continuous load (constant rate)
 *
 * Usage:
 *   k6 run scripts/load-test/workflow-execution.js
 *   k6 run --env BASE_URL=https://talos.example.com scripts/load-test/workflow-execution.js
 *   k6 run --env TEST_EMAIL=perf@example.com --env TEST_PASSWORD=secret123 scripts/load-test/workflow-execution.js
 */

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Counter, Trend, Rate } from 'k6/metrics';

// ---------------------------------------------------------------------------
// Custom metrics
// ---------------------------------------------------------------------------
const workflowExecutionDuration = new Trend('workflow_execution_duration', true);
const workflowSuccessRate = new Rate('workflow_success_rate');
const workflowsCreated = new Counter('workflows_created');
const executionsTriggered = new Counter('executions_triggered');
const approvalGateHits = new Counter('approval_gate_hits');

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const API_URL = `${BASE_URL}/graphql`;
const TEST_EMAIL = __ENV.TEST_EMAIL || 'loadtest@example.com';
const TEST_PASSWORD = __ENV.TEST_PASSWORD || 'LoadTest!2026';

export const options = {
  scenarios: {
    // Scenario 1: Sustained workflow creation and execution
    sustained_execution: {
      executor: 'constant-vus',
      vus: parseInt(__ENV.SUSTAINED_VUS || '10'),
      duration: __ENV.SUSTAINED_DURATION || '2m',
      exec: 'sustainedExecution',
      tags: { scenario: 'sustained' },
    },
    // Scenario 2: Burst of concurrent workflow triggers
    burst_trigger: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '10s', target: parseInt(__ENV.BURST_PEAK || '50') },
        { duration: '30s', target: parseInt(__ENV.BURST_PEAK || '50') },
        { duration: '10s', target: 0 },
      ],
      exec: 'burstTrigger',
      startTime: '2m30s',  // Start after sustained test
      tags: { scenario: 'burst' },
    },
    // Scenario 3: Health endpoint under load
    health_check: {
      executor: 'constant-rate',
      rate: parseInt(__ENV.HEALTH_RPS || '100'),
      timeUnit: '1s',
      duration: '3m',
      preAllocatedVUs: 20,
      exec: 'healthCheck',
      tags: { scenario: 'health' },
    },
  },
  thresholds: {
    'workflow_execution_duration': ['p(95)<5000', 'p(99)<10000'],
    'workflow_success_rate': ['rate>0.95'],
    'http_req_duration': ['p(95)<2000'],
    'http_req_failed': ['rate<0.05'],
  },
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Extract a CSRF token from a response's Set-Cookie header.
 */
function extractCsrfToken(response) {
  const cookies = response.cookies;
  if (cookies && cookies.talos_csrf) {
    return cookies.talos_csrf[0].value;
  }
  return null;
}

/**
 * Send a GraphQL request with optional auth token and CSRF token.
 */
function graphql(query, variables, token, csrfToken) {
  const headers = {
    'Content-Type': 'application/json',
    'X-Trace-ID': `k6-${__VU}-${__ITER}-${Date.now()}`,
  };
  if (csrfToken) {
    headers['X-CSRF-Token'] = csrfToken;
  }
  if (token) {
    headers['Cookie'] = `access_token=${token}`;
  }

  const res = http.post(API_URL, JSON.stringify({ query, variables: variables || {} }), {
    headers,
    tags: { name: 'graphql' },
  });
  return res;
}

/**
 * Authenticate and return { accessToken, csrfToken }.
 * Returns null tokens on failure so callers can bail gracefully.
 */
function login() {
  // Seed CSRF cookie
  const seedRes = http.get(`${BASE_URL}/graphql`);
  let csrfToken = extractCsrfToken(seedRes);

  const res = graphql(`
    mutation Login($input: LoginInput!) {
      login(input: $input) {
        accessToken
        refreshToken
        user { id email name }
      }
    }
  `, {
    input: { email: TEST_EMAIL, password: TEST_PASSWORD },
  }, null, csrfToken);

  // Refresh CSRF if rotated
  const newCsrf = extractCsrfToken(res);
  if (newCsrf) {
    csrfToken = newCsrf;
  }

  let accessToken = null;
  try {
    const body = JSON.parse(res.body);
    accessToken = body.data && body.data.login ? body.data.login.accessToken : null;
  } catch {
    // ignore parse errors
  }

  return { accessToken, csrfToken };
}

/**
 * Parse a GraphQL JSON response body safely.
 */
function parseBody(res) {
  try {
    return JSON.parse(res.body);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Scenario 1: Sustained execution
// ---------------------------------------------------------------------------
export function sustainedExecution() {
  const auth = login();
  if (!auth.accessToken) {
    sleep(1);
    return;
  }

  group('create_and_execute_workflow', () => {
    // List existing workflows
    const listRes = graphql(`
      query ListWorkflows($pagination: PaginationInput) {
        workflows(pagination: $pagination) {
          id
          name
        }
      }
    `, { pagination: { limit: 20, offset: 0 } }, auth.accessToken, auth.csrfToken);

    check(listRes, {
      'list workflows: status 200': (r) => r.status === 200,
    });

    const listBody = parseBody(listRes);
    const workflows = (listBody && listBody.data && listBody.data.workflows) || [];

    // Trigger execution on the first available workflow
    if (workflows.length > 0) {
      const workflowId = workflows[0].id;

      const start = Date.now();
      const execRes = graphql(`
        mutation TriggerWorkflow($workflowId: UUID!) {
          triggerWorkflow(workflowId: $workflowId)
        }
      `, { workflowId: workflowId }, auth.accessToken, auth.csrfToken);

      const duration = Date.now() - start;
      workflowExecutionDuration.add(duration);
      executionsTriggered.add(1);

      const execBody = parseBody(execRes);
      const success = execRes.status === 200 &&
        execBody && execBody.data && !execBody.errors;
      workflowSuccessRate.add(success ? 1 : 0);

      // Check if the response mentions an approval gate
      if (execBody && execBody.data && execBody.data.triggerWorkflow) {
        const result = JSON.stringify(execBody.data.triggerWorkflow);
        if (result.includes('approval') || result.includes('pending')) {
          approvalGateHits.add(1);
        }
      }
    }
  });

  sleep(1);
}

// ---------------------------------------------------------------------------
// Scenario 2: Burst trigger
// ---------------------------------------------------------------------------
export function burstTrigger() {
  const auth = login();
  if (!auth.accessToken) {
    sleep(0.5);
    return;
  }

  // Fetch a workflow to trigger
  const listRes = graphql(`
    query ListWorkflows($pagination: PaginationInput) {
      workflows(pagination: $pagination) {
        id
      }
    }
  `, { pagination: { limit: 5, offset: 0 } }, auth.accessToken, auth.csrfToken);

  const listBody = parseBody(listRes);
  const workflows = (listBody && listBody.data && listBody.data.workflows) || [];

  if (workflows.length > 0) {
    const workflowId = workflows[0].id;

    const start = Date.now();
    const res = graphql(`
      mutation TriggerWorkflow($workflowId: UUID!) {
        triggerWorkflow(workflowId: $workflowId)
      }
    `, { workflowId: workflowId }, auth.accessToken, auth.csrfToken);

    workflowExecutionDuration.add(Date.now() - start);
    executionsTriggered.add(1);

    check(res, {
      'burst execution: status 200': (r) => r.status === 200,
      'burst execution: no server error': (r) => r.status !== 500,
    });
  }

  sleep(0.1);
}

// ---------------------------------------------------------------------------
// Scenario 3: Health check
// ---------------------------------------------------------------------------
export function healthCheck() {
  const res = http.get(`${BASE_URL}/health`, {
    tags: { name: 'health' },
  });
  check(res, {
    'health: status 200': (r) => r.status === 200,
    'health: has checks object': (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.checks !== undefined;
      } catch {
        return false;
      }
    },
  });
}

// ---------------------------------------------------------------------------
// Setup / Teardown
// ---------------------------------------------------------------------------
export function setup() {
  // Verify the target is reachable
  const res = http.get(`${BASE_URL}/health`);
  const ok = check(res, {
    'health check passes': (r) => r.status === 200,
  });

  if (!ok) {
    console.error(`Target ${BASE_URL} is not reachable. Aborting test.`);
  }

  // Verify login works
  const seedRes = http.get(`${BASE_URL}/graphql`);
  let csrfToken = null;
  if (seedRes.cookies && seedRes.cookies.talos_csrf) {
    csrfToken = seedRes.cookies.talos_csrf[0].value;
  }

  const headers = { 'Content-Type': 'application/json' };
  if (csrfToken) {
    headers['X-CSRF-Token'] = csrfToken;
  }

  const loginRes = http.post(API_URL, JSON.stringify({
    query: `
      mutation Login($input: LoginInput!) {
        login(input: $input) { accessToken user { id email } }
      }
    `,
    variables: { input: { email: TEST_EMAIL, password: TEST_PASSWORD } },
  }), { headers });

  let loginOk = false;
  try {
    const body = JSON.parse(loginRes.body);
    loginOk = body.data && body.data.login && body.data.login.accessToken;
  } catch {
    // ignore
  }

  if (!loginOk) {
    console.warn(`Login failed for ${TEST_EMAIL}. Verify credentials are correct.`);
    console.warn('Test will continue but all authenticated requests will fail.');
  }

  return { baseUrl: BASE_URL, email: TEST_EMAIL };
}

export function teardown(data) {
  console.log(`\nWorkflow execution pipeline test completed`);
  console.log(`  Target: ${data.baseUrl}`);
  console.log(`  User:   ${data.email}`);
}
