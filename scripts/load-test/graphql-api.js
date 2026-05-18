/**
 * k6 Load Test: Talos GraphQL API
 *
 * Covers the primary API operations:
 *   1. Login (authentication)
 *   2. List workflows
 *   3. Create workflow
 *   4. Trigger execution
 *   5. List secrets
 *
 * Usage:
 *   k6 run scripts/load-test/graphql-api.js
 *   k6 run --env BASE_URL=https://talos.example.com scripts/load-test/graphql-api.js
 *   k6 run --env VUS=50 --env DURATION=2m scripts/load-test/graphql-api.js
 */

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';

// ---------------------------------------------------------------------------
// Custom metrics
// ---------------------------------------------------------------------------
const loginDuration = new Trend('login_duration', true);
const listWorkflowsDuration = new Trend('list_workflows_duration', true);
const createWorkflowDuration = new Trend('create_workflow_duration', true);
const triggerExecutionDuration = new Trend('trigger_execution_duration', true);
const listSecretsDuration = new Trend('list_secrets_duration', true);
const graphqlErrors = new Counter('graphql_errors');
const authFailures = new Rate('auth_failures');

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const TEST_EMAIL = __ENV.TEST_EMAIL || 'loadtest@example.com';
const TEST_PASSWORD = __ENV.TEST_PASSWORD || 'LoadTest!2026';

export const options = {
  stages: [
    { duration: __ENV.RAMP_UP || '30s', target: parseInt(__ENV.VUS_RAMP || '20') },
    { duration: __ENV.SUSTAIN || '1m', target: parseInt(__ENV.VUS || '50') },
    { duration: __ENV.PEAK || '30s', target: parseInt(__ENV.VUS_PEAK || '100') },
    { duration: __ENV.RAMP_DOWN || '30s', target: 0 },
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'],     // 95th percentile under 500ms
    http_req_failed: ['rate<0.01'],        // Less than 1% failure rate
    login_duration: ['p(95)<1000'],        // Login under 1s at p95
    list_workflows_duration: ['p(95)<300'],// List workflows under 300ms
    create_workflow_duration: ['p(95)<500'],
    graphql_errors: ['count<100'],         // Fewer than 100 GraphQL errors total
    auth_failures: ['rate<0.05'],          // Less than 5% auth failures
  },
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function graphqlPost(url, query, variables, cookies, csrfToken) {
  const headers = {
    'Content-Type': 'application/json',
  };
  if (csrfToken) {
    headers['X-CSRF-Token'] = csrfToken;
  }

  const jar = cookies || http.cookieJar();
  const payload = JSON.stringify({ query, variables });

  return http.post(`${url}/graphql`, payload, {
    headers,
    tags: { name: 'graphql' },
  });
}

function extractCsrfToken(response) {
  // The CSRF token may be set as a cookie named talos_csrf
  const cookies = response.cookies;
  if (cookies && cookies.talos_csrf) {
    return cookies.talos_csrf[0].value;
  }
  return null;
}

function checkGraphQLResponse(response, operationName) {
  const success = check(response, {
    [`${operationName}: status is 200`]: (r) => r.status === 200,
    [`${operationName}: no errors`]: (r) => {
      try {
        const body = JSON.parse(r.body);
        return !body.errors || body.errors.length === 0;
      } catch {
        return false;
      }
    },
    [`${operationName}: has data`]: (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.data !== undefined && body.data !== null;
      } catch {
        return false;
      }
    },
  });

  if (!success) {
    graphqlErrors.add(1);
  }

  return success;
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

/**
 * Seed the CSRF cookie with an initial GET request.
 */
function seedCsrf() {
  const res = http.get(`${BASE_URL}/graphql`);
  return extractCsrfToken(res);
}

/**
 * Scenario 1: Login
 */
function doLogin(csrfToken) {
  const query = `
    mutation Login($input: LoginInput!) {
      login(input: $input) {
        accessToken
        refreshToken
        user { id email name }
      }
    }
  `;
  const variables = {
    input: {
      email: TEST_EMAIL,
      password: TEST_PASSWORD,
    },
  };

  const start = Date.now();
  const res = graphqlPost(BASE_URL, query, variables, null, csrfToken);
  loginDuration.add(Date.now() - start);

  const ok = checkGraphQLResponse(res, 'login');
  if (!ok) {
    authFailures.add(1);
  } else {
    authFailures.add(0);
  }

  // Extract new CSRF token if rotated
  const newCsrf = extractCsrfToken(res);

  let accessToken = null;
  try {
    const body = JSON.parse(res.body);
    accessToken = body.data?.login?.accessToken;
  } catch {
    // ignore
  }

  return { accessToken, csrfToken: newCsrf || csrfToken };
}

/**
 * Scenario 2: List Workflows
 */
function doListWorkflows(csrfToken) {
  const query = `
    query ListWorkflows($pagination: PaginationInput) {
      workflows(pagination: $pagination) {
        id
        name
        graphJson
      }
    }
  `;
  const variables = { pagination: { limit: 20, offset: 0 } };

  const start = Date.now();
  const res = graphqlPost(BASE_URL, query, variables, null, csrfToken);
  listWorkflowsDuration.add(Date.now() - start);

  checkGraphQLResponse(res, 'listWorkflows');

  let workflowIds = [];
  try {
    const body = JSON.parse(res.body);
    workflowIds = (body.data?.workflows || []).map((w) => w.id);
  } catch {
    // ignore
  }

  return workflowIds;
}

/**
 * Scenario 3: Create Workflow
 */
function doCreateWorkflow(csrfToken) {
  const query = `
    mutation CreateWorkflow($input: CreateWorkflowInput!) {
      createWorkflow(input: $input) {
        id
        name
        graphJson
      }
    }
  `;

  const uniqueName = `load-test-workflow-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const graphJson = JSON.stringify({
    nodes: [
      {
        id: 'n1',
        type: 'talosNode',
        position: { x: 100, y: 100 },
        data: { label: 'Echo Node', moduleId: 'echo-module', moduleName: 'Echo' },
      },
    ],
    edges: [],
  });

  const variables = {
    input: {
      name: uniqueName,
      graphJson: graphJson,
    },
  };

  const start = Date.now();
  const res = graphqlPost(BASE_URL, query, variables, null, csrfToken);
  createWorkflowDuration.add(Date.now() - start);

  checkGraphQLResponse(res, 'createWorkflow');

  let workflowId = null;
  try {
    const body = JSON.parse(res.body);
    workflowId = body.data?.createWorkflow?.id;
  } catch {
    // ignore
  }

  return workflowId;
}

/**
 * Scenario 4: Trigger Execution
 */
function doTriggerExecution(workflowId, csrfToken) {
  if (!workflowId) return;

  const query = `
    mutation TriggerWorkflow($workflowId: UUID!) {
      triggerWorkflow(workflowId: $workflowId)
    }
  `;
  const variables = { workflowId };

  const start = Date.now();
  const res = graphqlPost(BASE_URL, query, variables, null, csrfToken);
  triggerExecutionDuration.add(Date.now() - start);

  checkGraphQLResponse(res, 'triggerExecution');
}

/**
 * Scenario 5: List Secrets
 */
function doListSecrets(csrfToken) {
  const query = `
    query ListSecrets($pagination: PaginationInput) {
      secrets(pagination: $pagination) {
        id
        name
        keyPath
        description
        createdAt
      }
    }
  `;
  const variables = { pagination: { limit: 50, offset: 0 } };

  const start = Date.now();
  const res = graphqlPost(BASE_URL, query, variables, null, csrfToken);
  listSecretsDuration.add(Date.now() - start);

  checkGraphQLResponse(res, 'listSecrets');
}

// ---------------------------------------------------------------------------
// Main VU function
// ---------------------------------------------------------------------------
export default function () {
  // 1. Seed CSRF
  let csrfToken = seedCsrf();

  // 2. Login
  group('login', () => {
    const result = doLogin(csrfToken);
    csrfToken = result.csrfToken;
  });

  sleep(0.5);

  // 3. List workflows
  let workflowIds = [];
  group('list_workflows', () => {
    workflowIds = doListWorkflows(csrfToken);
  });

  sleep(0.3);

  // 4. Create a new workflow
  let newWorkflowId = null;
  group('create_workflow', () => {
    newWorkflowId = doCreateWorkflow(csrfToken);
  });

  sleep(0.3);

  // 5. Trigger execution on the new workflow (or an existing one)
  group('trigger_execution', () => {
    const targetId = newWorkflowId || (workflowIds.length > 0 ? workflowIds[0] : null);
    doTriggerExecution(targetId, csrfToken);
  });

  sleep(0.3);

  // 6. List secrets
  group('list_secrets', () => {
    doListSecrets(csrfToken);
  });

  sleep(1);
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
    // k6 will still run but all requests will likely fail
  }

  return { baseUrl: BASE_URL };
}

export function teardown(data) {
  console.log(`Load test completed against ${data.baseUrl}`);
}
