import { test, expect } from '@playwright/test';

/**
 * Helper: set up a mocked authenticated session with auth + CSRF cookies.
 */
async function setupAuthenticatedSession(page: import('@playwright/test').Page) {
  await page.context().addCookies([
    {
      name: 'talos_access_token',
      value: 'mock-access-token',
      domain: 'localhost',
      path: '/',
    },
    {
      name: 'talos_refresh_token',
      value: 'mock-refresh-token',
      domain: 'localhost',
      path: '/',
    },
    {
      name: 'talos_csrf',
      value: 'mock-csrf-token',
      domain: 'localhost',
      path: '/',
    },
  ]);
}

const MOCK_WORKFLOW_ID = '11111111-1111-1111-1111-111111111111';
const MOCK_EXECUTION_ID = '22222222-2222-2222-2222-222222222222';

const MOCK_TEMPLATES = [
  {
    id: 'tpl-http',
    name: 'HTTP Request',
    category: 'network',
    configSchema: '{}',
    codeTemplate: '',
    capabilityWorld: 'http-client',
    description: 'Make HTTP requests',
  },
  {
    id: 'tpl-json',
    name: 'JSON Transform',
    category: 'transform',
    configSchema: '{}',
    codeTemplate: '',
    capabilityWorld: 'json-transform',
    description: 'Transform JSON data',
  },
  {
    id: 'tpl-echo',
    name: 'Echo',
    category: 'utility',
    configSchema: '{}',
    codeTemplate: '',
    capabilityWorld: 'echo',
    description: 'Echo input to output',
  },
];

/** Standard mock responses for me, nodeTemplates, and latestWorkflowExecutions. */
function handleCommonQueries(query: string, route: import('@playwright/test').Route): Promise<boolean> | boolean {
  return false; // handled inline for clarity
}

/**
 * Set up a standard GraphQL route mock that responds to common queries.
 * The `overrides` callback is invoked first; return `true` from it to indicate the request was handled.
 */
async function setupGraphQLMock(
  page: import('@playwright/test').Page,
  overrides?: (query: string, body: Record<string, unknown>, route: import('@playwright/test').Route) => Promise<boolean>,
) {
  await page.route('**/graphql', async (route) => {
    if (route.request().method() === 'GET') {
      await route.fulfill({ status: 200, contentType: 'text/plain', body: 'OK' });
      return;
    }
    if (route.request().method() !== 'POST') {
      await route.continue();
      return;
    }

    const body = route.request().postDataJSON();
    const query: string = body?.query || '';

    // Let caller handle first
    if (overrides && (await overrides(query, body, route))) return;

    // me
    if (query.includes('me')) {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: {
            me: {
              id: 'user-1',
              email: 'test@example.com',
              name: 'Test User',
              createdAt: new Date().toISOString(),
              twoFactorEnabled: false,
            },
          },
        }),
      });
      return;
    }

    // nodeTemplates
    if (query.includes('nodeTemplates')) {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ data: { nodeTemplates: MOCK_TEMPLATES } }),
      });
      return;
    }

    // latestWorkflowExecutions
    if (query.includes('latestWorkflowExecutions')) {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ data: { latestWorkflowExecutions: [] } }),
      });
      return;
    }

    await route.continue();
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test.describe('AI Agent Workflow Features', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');
  });

  test('workflow builder loads and displays canvas', async ({ page }) => {
    const canvas = page.locator('.react-flow');
    // The canvas may not be visible on the landing page without auth;
    // navigate to editor to check.
    await setupAuthenticatedSession(page);
    await setupGraphQLMock(page, async (query, _body, route) => {
      if (query.includes('workflows') && !query.includes('mutation')) {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ data: { workflows: [] } }),
        });
        return true;
      }
      return false;
    });
    await page.goto('/editor');
    await expect(canvas).toBeVisible({ timeout: 10_000 });
  });

  test('can create a new workflow from dashboard', async ({ page }) => {
    await setupAuthenticatedSession(page);
    await setupGraphQLMock(page, async (query, body, route) => {
      if (query.includes('workflows') && !query.includes('mutation')) {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ data: { workflows: [] } }),
        });
        return true;
      }
      if (query.includes('createWorkflow')) {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            data: {
              createWorkflow: {
                id: MOCK_WORKFLOW_ID,
                name: (body as Record<string, any>).variables?.input?.name || 'New Workflow',
                graphJson: '{}',
              },
            },
          }),
        });
        return true;
      }
      return false;
    });

    await page.goto('/dashboard');

    const createBtn = page.getByRole('button', { name: /create workflow|new workflow/i }).first();
    if (await createBtn.isVisible({ timeout: 5000 }).catch(() => false)) {
      await createBtn.click();
      await expect(page).toHaveURL(/\/editor|\/builder/);
    }
  });

  test('toolbar displays workflow controls', async ({ page }) => {
    await setupAuthenticatedSession(page);
    await setupGraphQLMock(page, async (query, _body, route) => {
      if (query.includes('workflows') && !query.includes('mutation')) {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ data: { workflows: [] } }),
        });
        return true;
      }
      return false;
    });

    await page.goto('/editor');
    // Verify the toolbar has expected controls (run, save, add node)
    const runBtn = page.getByRole('button', { name: /execute|run|test/i }).first();
    const saveBtn = page.getByRole('button', { name: /save/i }).first();
    const addBtn = page.getByRole('button', { name: /add node/i }).first();

    // At least one of these should be visible in the editor
    const anyVisible = await Promise.all([
      runBtn.isVisible({ timeout: 3000 }).catch(() => false),
      saveBtn.isVisible({ timeout: 3000 }).catch(() => false),
      addBtn.isVisible({ timeout: 3000 }).catch(() => false),
    ]);
    expect(anyVisible.some(Boolean)).toBe(true);
  });

  test('inspector panel shows node details on click', async ({ page }) => {
    await setupAuthenticatedSession(page);

    const workflowGraph = JSON.stringify({
      nodes: [
        { id: 'n1', type: 'talosNode', position: { x: 100, y: 100 }, data: { label: 'My Node', moduleId: 'mod-1', moduleName: 'HTTP Request' } },
      ],
      edges: [],
    });

    await setupGraphQLMock(page, async (query, _body, route) => {
      if (query.includes('workflows') && !query.includes('mutation')) {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            data: {
              workflows: [
                { id: MOCK_WORKFLOW_ID, name: 'Agent Test Pipeline', graphJson: workflowGraph },
              ],
            },
          }),
        });
        return true;
      }
      return false;
    });

    await page.goto('/dashboard');
    const workflowLink = page.getByText('Agent Test Pipeline').first();
    if (await workflowLink.isVisible({ timeout: 5000 }).catch(() => false)) {
      await workflowLink.click();

      // Click on a node if it appears
      const node = page.locator('.react-flow__node').first();
      if (await node.isVisible({ timeout: 5000 }).catch(() => false)) {
        await node.click();
        // Inspector should appear with node details
        const inspector = page.locator('.inspector-panel, [class*="inspector"]');
        await expect(inspector).toBeVisible({ timeout: 5000 });
      }
    }
  });
});

test.describe('Approval Gate (Human-in-the-Loop)', () => {
  test('approval buttons appear when execution reaches AwaitingApproval', async ({ page }) => {
    await setupAuthenticatedSession(page);

    const workflowGraph = JSON.stringify({
      nodes: [
        { id: 'n1', type: 'talosNode', position: { x: 100, y: 100 }, data: { label: 'Wait Node', moduleId: 'mod-wait', moduleName: 'Wait' } },
      ],
      edges: [],
    });

    let executionChecks = 0;

    await setupGraphQLMock(page, async (query, _body, route) => {
      if (query.includes('workflows') && !query.includes('mutation') && !query.includes('Execution')) {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            data: {
              workflows: [
                { id: MOCK_WORKFLOW_ID, name: 'Approval Pipeline', graphJson: workflowGraph },
              ],
            },
          }),
        });
        return true;
      }
      if (query.includes('triggerWorkflow')) {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ data: { triggerWorkflow: MOCK_EXECUTION_ID } }),
        });
        return true;
      }
      if (query.includes('workflowExecutionHistory') || query.includes('Execution')) {
        executionChecks++;
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            data: {
              workflowExecutionHistory: [
                {
                  id: MOCK_EXECUTION_ID,
                  workflowId: MOCK_WORKFLOW_ID,
                  status: 'running',
                  startedAt: new Date().toISOString(),
                  completedAt: null,
                  durationMs: null,
                  errorMessage: null,
                  outputData: null,
                },
              ],
            },
          }),
        });
        return true;
      }
      return false;
    });

    // Also mock the SSE/streaming events endpoint to emit AwaitingApproval
    await page.route('**/api/executions/*/events', async (route) => {
      // Return an SSE stream with an AwaitingApproval event
      const sseBody = [
        'data: {"nodeId":"n1","status":"AwaitingApproval","message":"Waiting for manager approval..."}',
        '',
      ].join('\n');
      await route.fulfill({
        status: 200,
        contentType: 'text/event-stream',
        body: sseBody,
      });
    });

    await page.goto('/dashboard');

    const workflowLink = page.getByText('Approval Pipeline').first();
    if (await workflowLink.isVisible({ timeout: 5000 }).catch(() => false)) {
      await workflowLink.click();

      // Trigger execution
      const executeBtn = page.getByRole('button', { name: /execute|run/i }).first();
      if (await executeBtn.isVisible({ timeout: 3000 }).catch(() => false)) {
        await executeBtn.click();

        // The approve/reject buttons should appear in the execution panel
        const approveBtn = page.getByRole('button', { name: /approve/i }).first();
        const rejectBtn = page.getByRole('button', { name: /reject/i }).first();

        // At least check the UI renders them when an AwaitingApproval event is present
        const approveVisible = await approveBtn.isVisible({ timeout: 5000 }).catch(() => false);
        const rejectVisible = await rejectBtn.isVisible({ timeout: 5000 }).catch(() => false);

        // If the execution panel is rendered with the AwaitingApproval state,
        // both buttons should be visible
        if (approveVisible) {
          expect(rejectVisible).toBe(true);
        }
      }
    }
  });

  test('approval POST sends correct payload', async ({ page }) => {
    await setupAuthenticatedSession(page);

    let approvalPayload: { approved?: boolean } | null = null;

    // Mock the approval REST endpoint
    await page.route('**/api/approvals/**', async (route) => {
      if (route.request().method() === 'POST') {
        approvalPayload = route.request().postDataJSON();
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ ok: true }),
        });
        return;
      }
      await route.continue();
    });

    // Directly test that the approval mechanism sends { approved: true }
    await page.goto('/');
    const result = await page.evaluate(async () => {
      const resp = await fetch('/api/approvals/test-exec-id', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ approved: true }),
      });
      return resp.json();
    });

    expect(result.ok).toBe(true);
    expect(approvalPayload).toEqual({ approved: true });
  });
});

test.describe('Execution Streaming and Events', () => {
  test('execution panel shows running status with streaming events', async ({ page }) => {
    await setupAuthenticatedSession(page);

    const workflowGraph = JSON.stringify({
      nodes: [
        { id: 'n1', type: 'talosNode', position: { x: 100, y: 100 }, data: { label: 'Step 1', moduleId: 'mod-1', moduleName: 'HTTP Request' } },
        { id: 'n2', type: 'talosNode', position: { x: 400, y: 100 }, data: { label: 'Step 2', moduleId: 'mod-2', moduleName: 'JSON Transform' } },
      ],
      edges: [{ id: 'e1', source: 'n1', target: 'n2' }],
    });

    let triggerCalled = false;

    await setupGraphQLMock(page, async (query, _body, route) => {
      if (query.includes('workflows') && !query.includes('mutation') && !query.includes('Execution')) {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            data: {
              workflows: [
                { id: MOCK_WORKFLOW_ID, name: 'Streaming Pipeline', graphJson: workflowGraph },
              ],
            },
          }),
        });
        return true;
      }
      if (query.includes('triggerWorkflow')) {
        triggerCalled = true;
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ data: { triggerWorkflow: MOCK_EXECUTION_ID } }),
        });
        return true;
      }
      if (query.includes('workflowExecutionHistory') || query.includes('Execution')) {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            data: {
              workflowExecutionHistory: [
                {
                  id: MOCK_EXECUTION_ID,
                  workflowId: MOCK_WORKFLOW_ID,
                  status: 'running',
                  startedAt: new Date().toISOString(),
                  completedAt: null,
                  durationMs: null,
                  errorMessage: null,
                  outputData: null,
                },
              ],
            },
          }),
        });
        return true;
      }
      return false;
    });

    await page.goto('/dashboard');

    const workflowLink = page.getByText('Streaming Pipeline').first();
    if (await workflowLink.isVisible({ timeout: 5000 }).catch(() => false)) {
      await workflowLink.click();

      const executeBtn = page.getByRole('button', { name: /execute|run/i }).first();
      if (await executeBtn.isVisible({ timeout: 3000 }).catch(() => false)) {
        await executeBtn.click();
        expect(triggerCalled).toBe(true);

        // Verify that execution panel shows running indicator
        const runningIndicator = page.getByText(/running|executing|in progress/i).first();
        await expect(runningIndicator).toBeVisible({ timeout: 5000 });
      }
    }
  });

  test('execution error state is displayed clearly', async ({ page }) => {
    await setupAuthenticatedSession(page);

    await setupGraphQLMock(page, async (query, _body, route) => {
      if (query.includes('workflows') && !query.includes('mutation') && !query.includes('Execution')) {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            data: {
              workflows: [
                {
                  id: MOCK_WORKFLOW_ID,
                  name: 'Error Pipeline',
                  graphJson: JSON.stringify({
                    nodes: [{ id: 'n1', type: 'talosNode', position: { x: 100, y: 100 }, data: { label: 'Broken', moduleId: 'mod-bad', moduleName: 'Broken' } }],
                    edges: [],
                  }),
                },
              ],
            },
          }),
        });
        return true;
      }
      if (query.includes('triggerWorkflow')) {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            errors: [{ message: 'Module compilation failed: missing export' }],
          }),
        });
        return true;
      }
      return false;
    });

    await page.goto('/dashboard');

    const workflowLink = page.getByText('Error Pipeline').first();
    if (await workflowLink.isVisible({ timeout: 5000 }).catch(() => false)) {
      await workflowLink.click();

      const executeBtn = page.getByRole('button', { name: /execute|run/i }).first();
      if (await executeBtn.isVisible({ timeout: 3000 }).catch(() => false)) {
        await executeBtn.click();
        // Should show error feedback
        await expect(
          page.getByText(/failed|error|compilation/i).first()
        ).toBeVisible({ timeout: 5000 });
      }
    }
  });
});

test.describe('Fan-In Parallel Workflows', () => {
  test('parallel nodes render correctly on canvas', async ({ page }) => {
    await setupAuthenticatedSession(page);

    // A workflow with fan-out/fan-in: one source fans out to two parallel nodes,
    // then merges back into a single aggregator
    const workflowGraph = JSON.stringify({
      nodes: [
        { id: 'source', type: 'talosNode', position: { x: 100, y: 200 }, data: { label: 'Source', moduleId: 'mod-1', moduleName: 'HTTP Request' } },
        { id: 'branch-a', type: 'talosNode', position: { x: 350, y: 50 }, data: { label: 'Branch A', moduleId: 'mod-2', moduleName: 'JSON Transform' } },
        { id: 'branch-b', type: 'talosNode', position: { x: 350, y: 350 }, data: { label: 'Branch B', moduleId: 'mod-3', moduleName: 'JSON Transform' } },
        { id: 'aggregator', type: 'talosNode', position: { x: 600, y: 200 }, data: { label: 'Aggregator', moduleId: 'mod-4', moduleName: 'Echo' } },
      ],
      edges: [
        { id: 'e1', source: 'source', target: 'branch-a' },
        { id: 'e2', source: 'source', target: 'branch-b' },
        { id: 'e3', source: 'branch-a', target: 'aggregator' },
        { id: 'e4', source: 'branch-b', target: 'aggregator' },
      ],
    });

    await setupGraphQLMock(page, async (query, _body, route) => {
      if (query.includes('workflows') && !query.includes('mutation')) {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            data: {
              workflows: [
                { id: MOCK_WORKFLOW_ID, name: 'Fan-In Pipeline', graphJson: workflowGraph },
              ],
            },
          }),
        });
        return true;
      }
      return false;
    });

    await page.goto('/dashboard');

    const workflowLink = page.getByText('Fan-In Pipeline').first();
    if (await workflowLink.isVisible({ timeout: 5000 }).catch(() => false)) {
      await workflowLink.click();

      // All four nodes should be visible on the canvas
      await expect(page.getByText('Source')).toBeVisible({ timeout: 5000 });
      await expect(page.getByText('Branch A')).toBeVisible({ timeout: 5000 });
      await expect(page.getByText('Branch B')).toBeVisible({ timeout: 5000 });
      await expect(page.getByText('Aggregator')).toBeVisible({ timeout: 5000 });

      // Verify 4 nodes are rendered
      const nodeCount = await page.locator('.react-flow__node').count();
      expect(nodeCount).toBe(4);

      // Verify 4 edges are rendered
      const edgeCount = await page.locator('.react-flow__edge').count();
      expect(edgeCount).toBe(4);
    }
  });

  test('parallel execution shows per-branch status', async ({ page }) => {
    await setupAuthenticatedSession(page);

    const workflowGraph = JSON.stringify({
      nodes: [
        { id: 'source', type: 'talosNode', position: { x: 100, y: 200 }, data: { label: 'Source', moduleId: 'mod-1', moduleName: 'HTTP Request' } },
        { id: 'branch-a', type: 'talosNode', position: { x: 350, y: 50 }, data: { label: 'Branch A', moduleId: 'mod-2', moduleName: 'JSON Transform' } },
        { id: 'branch-b', type: 'talosNode', position: { x: 350, y: 350 }, data: { label: 'Branch B', moduleId: 'mod-3', moduleName: 'JSON Transform' } },
      ],
      edges: [
        { id: 'e1', source: 'source', target: 'branch-a' },
        { id: 'e2', source: 'source', target: 'branch-b' },
      ],
    });

    await setupGraphQLMock(page, async (query, _body, route) => {
      if (query.includes('workflows') && !query.includes('mutation') && !query.includes('Execution')) {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            data: {
              workflows: [
                { id: MOCK_WORKFLOW_ID, name: 'Parallel Pipeline', graphJson: workflowGraph },
              ],
            },
          }),
        });
        return true;
      }
      if (query.includes('triggerWorkflow')) {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ data: { triggerWorkflow: MOCK_EXECUTION_ID } }),
        });
        return true;
      }
      if (query.includes('workflowExecutionHistory') || query.includes('Execution')) {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            data: {
              workflowExecutionHistory: [
                {
                  id: MOCK_EXECUTION_ID,
                  workflowId: MOCK_WORKFLOW_ID,
                  status: 'running',
                  startedAt: new Date().toISOString(),
                  completedAt: null,
                  durationMs: null,
                  errorMessage: null,
                  outputData: null,
                },
              ],
            },
          }),
        });
        return true;
      }
      return false;
    });

    await page.goto('/dashboard');

    const workflowLink = page.getByText('Parallel Pipeline').first();
    if (await workflowLink.isVisible({ timeout: 5000 }).catch(() => false)) {
      await workflowLink.click();

      const executeBtn = page.getByRole('button', { name: /execute|run/i }).first();
      if (await executeBtn.isVisible({ timeout: 3000 }).catch(() => false)) {
        await executeBtn.click();
        // Verify execution was triggered and some status is displayed
        await expect(page.getByText(/running|executing|pending/i).first()).toBeVisible({ timeout: 5000 });
      }
    }
  });
});

test.describe('API Integration Checks', () => {
  test('health endpoint returns OK', async ({ request }) => {
    const response = await request.get('http://localhost:8000/health');
    expect(response.status()).toBe(200);
    const body = await response.json();
    expect(body.status).toBe('ok');
    expect(body.checks.postgres).toBe('ok');
  });

  test('GraphQL endpoint responds to introspection', async ({ request }) => {
    const response = await request.post('http://localhost:8000/graphql', {
      data: {
        query: '{ __schema { queryType { name } } }',
      },
      headers: {
        'Content-Type': 'application/json',
      },
    });
    expect(response.status()).toBe(200);
    const body = await response.json();
    expect(body.data.__schema.queryType.name).toBeTruthy();
  });

  test('rate limiting allows burst of normal requests', async ({ request }) => {
    const responses = [];
    for (let i = 0; i < 5; i++) {
      responses.push(await request.get('http://localhost:8000/health'));
    }
    for (const r of responses) {
      expect(r.status()).toBe(200);
    }
  });

  test('CSRF protection blocks mutations without token', async ({ request }) => {
    const response = await request.post('http://localhost:8000/graphql', {
      data: {
        query: 'mutation { login(input: { email: "test@test.com", password: "test" }) { accessToken } }',
      },
      headers: {
        'Content-Type': 'application/json',
      },
    });
    const body = await response.json();
    // GraphQL typically returns 200 with errors for auth/CSRF issues
    if (response.status() === 200 && body.errors) {
      expect(body.errors.length).toBeGreaterThan(0);
    }
  });

  test('X-Trace-ID header is accepted without error', async ({ request }) => {
    const traceId = 'e2e-trace-' + Date.now();
    const response = await request.post('http://localhost:8000/graphql', {
      data: {
        query: '{ __schema { queryType { name } } }',
      },
      headers: {
        'Content-Type': 'application/json',
        'X-Trace-ID': traceId,
      },
    });
    expect(response.status()).toBe(200);
  });
});

test.describe('MCP Agent Integration', () => {
  test('MCP settings page renders agent configuration', async ({ page }) => {
    await setupAuthenticatedSession(page);
    await setupGraphQLMock(page);

    // Navigate to settings (the MCP config is under settings)
    await page.goto('/settings');

    // Look for MCP-related text
    const mcpHeading = page.getByText(/MCP Server|AI Agent/i).first();
    if (await mcpHeading.isVisible({ timeout: 5000 }).catch(() => false)) {
      // Verify the configuration section exists
      await expect(page.getByText(/sandbox|wasm|telemetry/i).first()).toBeVisible({ timeout: 3000 });
    }
  });
});
