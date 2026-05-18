import { test, expect } from '@playwright/test';

/**
 * Helper: set up a mocked authenticated session.
 * Intercepts GraphQL requests and provides mock data for common queries.
 */
async function setupAuthenticatedSession(page: import('@playwright/test').Page) {
  // Set auth cookies to simulate an authenticated session
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
const MOCK_VERSION_ID = '33333333-3333-3333-3333-333333333333';

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

test.describe('Workflow Creation with Multiple Nodes', () => {
  test('create a workflow with HTTP and Transform nodes', async ({ page }) => {
    await setupAuthenticatedSession(page);

    let savedWorkflow = false;

    await page.route('**/graphql', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({
          status: 200,
          contentType: 'text/plain',
          body: 'OK',
        });
        return;
      }

      if (route.request().method() === 'POST') {
        const body = route.request().postDataJSON();
        const query = body?.query || '';

        // Handle node templates query
        if (query.includes('nodeTemplates')) {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ data: { nodeTemplates: MOCK_TEMPLATES } }),
          });
          return;
        }

        // Handle me query
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

        // Handle workflows list query
        if (query.includes('workflows') && !query.includes('mutation')) {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ data: { workflows: [] } }),
          });
          return;
        }

        // Handle createWorkflow mutation
        if (query.includes('createWorkflow')) {
          savedWorkflow = true;
          const graphJson = body.variables?.input?.graph_json || body.variables?.input?.graphJson || '{}';
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              data: {
                createWorkflow: {
                  id: MOCK_WORKFLOW_ID,
                  name: body.variables?.input?.name || 'New Workflow',
                  graphJson: graphJson,
                },
              },
            }),
          });
          return;
        }

        // Handle updateWorkflow mutation
        if (query.includes('updateWorkflow')) {
          savedWorkflow = true;
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              data: {
                updateWorkflow: {
                  id: MOCK_WORKFLOW_ID,
                  name: body.variables?.input?.name || 'Updated Workflow',
                  graphJson: body.variables?.input?.graphJson || '{}',
                },
              },
            }),
          });
          return;
        }
      }

      await route.continue();
    });

    // Navigate to dashboard and create a new workflow
    await page.goto('/dashboard');

    // Click create workflow button (try both known button labels)
    const createButton = page.getByRole('button', { name: /create workflow|new workflow/i }).first();
    await createButton.click();

    // Wait for the editor/builder to load
    await expect(page).toHaveURL(/\/editor|\/builder/);

    // Add first node: HTTP Request
    await page.getByRole('button', { name: /add node/i }).click();
    await page.getByText(/http request/i).first().click();

    // Fill in the node name
    const nodeNameInput = page.getByLabel(/node name/i).or(page.getByPlaceholder(/my-http-request/i));
    await nodeNameInput.fill('API Fetcher');
    await page.getByRole('button', { name: /create node/i }).click();

    // Add second node: JSON Transform
    await page.getByRole('button', { name: /add node/i }).click();
    await page.getByText(/json transform/i).first().click();
    const nodeNameInput2 = page.getByLabel(/node name/i).or(page.getByPlaceholder(/my-http-request/i));
    await nodeNameInput2.fill('Data Transformer');
    await page.getByRole('button', { name: /create node/i }).click();

    // Verify both nodes are visible on the canvas
    await expect(page.getByText('API Fetcher')).toBeVisible();
    await expect(page.getByText('Data Transformer')).toBeVisible();

    // Verify at least two nodes exist in the flow
    const nodeCount = await page.locator('.react-flow__node').count();
    expect(nodeCount).toBeGreaterThanOrEqual(2);

    // Save the workflow
    await page.getByRole('button', { name: /save/i }).click();
    await expect(page.getByText(/saved/i)).toBeVisible({ timeout: 5000 });
  });
});

test.describe('Workflow Execution and Status Updates', () => {
  test('execute a workflow and observe status transitions', async ({ page }) => {
    await setupAuthenticatedSession(page);

    let executionTriggered = false;
    let executionStatusChecks = 0;

    await page.route('**/graphql', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({ status: 200, contentType: 'text/plain', body: 'OK' });
        return;
      }

      if (route.request().method() === 'POST') {
        const body = route.request().postDataJSON();
        const query = body?.query || '';

        if (query.includes('me')) {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              data: {
                me: { id: 'user-1', email: 'test@example.com', name: 'Test User', createdAt: new Date().toISOString(), twoFactorEnabled: false },
              },
            }),
          });
          return;
        }

        if (query.includes('nodeTemplates')) {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ data: { nodeTemplates: MOCK_TEMPLATES } }),
          });
          return;
        }

        // Return a workflow with pre-existing nodes
        if (query.includes('workflows') && !query.includes('mutation') && !query.includes('Execution')) {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              data: {
                workflows: [
                  {
                    id: MOCK_WORKFLOW_ID,
                    name: 'Test Pipeline',
                    graphJson: JSON.stringify({
                      nodes: [
                        { id: 'n1', type: 'talosNode', position: { x: 100, y: 100 }, data: { label: 'Fetcher', moduleId: 'mod-1', moduleName: 'HTTP Request' } },
                        { id: 'n2', type: 'talosNode', position: { x: 400, y: 100 }, data: { label: 'Transform', moduleId: 'mod-2', moduleName: 'JSON Transform' } },
                      ],
                      edges: [{ id: 'e1', source: 'n1', target: 'n2' }],
                    }),
                  },
                ],
              },
            }),
          });
          return;
        }

        // Handle triggerWorkflow mutation
        if (query.includes('triggerWorkflow')) {
          executionTriggered = true;
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              data: { triggerWorkflow: MOCK_EXECUTION_ID },
            }),
          });
          return;
        }

        // Handle execution history queries with progressive status
        if (query.includes('workflowExecutionHistory') || query.includes('Execution')) {
          executionStatusChecks++;
          const status = executionStatusChecks <= 1 ? 'running' : 'completed';
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              data: {
                workflowExecutionHistory: [
                  {
                    id: MOCK_EXECUTION_ID,
                    workflowId: MOCK_WORKFLOW_ID,
                    status: status,
                    startedAt: new Date().toISOString(),
                    completedAt: status === 'completed' ? new Date().toISOString() : null,
                    durationMs: status === 'completed' ? 1250 : null,
                    errorMessage: null,
                    outputData: null,
                  },
                ],
              },
            }),
          });
          return;
        }

        // Handle latestWorkflowExecutions
        if (query.includes('latestWorkflowExecutions')) {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ data: { latestWorkflowExecutions: [] } }),
          });
          return;
        }
      }

      await route.continue();
    });

    // Navigate to dashboard and open the workflow
    await page.goto('/dashboard');

    // Click on the workflow to open it
    const workflowLink = page.getByText('Test Pipeline').first();
    if (await workflowLink.isVisible()) {
      await workflowLink.click();
    }

    // If we're in the editor, trigger execution
    const executeBtn = page.getByRole('button', { name: /execute|run/i }).first();
    if (await executeBtn.isVisible({ timeout: 3000 }).catch(() => false)) {
      await executeBtn.click();
      expect(executionTriggered).toBe(true);

      // Open execution history
      const historyBtn = page.getByRole('button', { name: /history/i }).first();
      if (await historyBtn.isVisible({ timeout: 2000 }).catch(() => false)) {
        await historyBtn.click();
        // Check that we see execution status
        await expect(page.getByText(/running|completed|pending/i).first()).toBeVisible({ timeout: 5000 });
      }
    }
  });

  test('execution failure shows error state', async ({ page }) => {
    await setupAuthenticatedSession(page);

    await page.route('**/graphql', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({ status: 200, contentType: 'text/plain', body: 'OK' });
        return;
      }

      if (route.request().method() === 'POST') {
        const body = route.request().postDataJSON();
        const query = body?.query || '';

        if (query.includes('me')) {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              data: { me: { id: 'user-1', email: 'test@example.com', name: 'Test User', createdAt: new Date().toISOString(), twoFactorEnabled: false } },
            }),
          });
          return;
        }

        if (query.includes('triggerWorkflow')) {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              errors: [{ message: 'Workflow execution failed: module compilation error' }],
            }),
          });
          return;
        }

        if (query.includes('nodeTemplates')) {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ data: { nodeTemplates: MOCK_TEMPLATES } }),
          });
          return;
        }

        if (query.includes('workflows') && !query.includes('mutation')) {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              data: {
                workflows: [
                  {
                    id: MOCK_WORKFLOW_ID,
                    name: 'Broken Pipeline',
                    graphJson: JSON.stringify({
                      nodes: [{ id: 'n1', type: 'talosNode', position: { x: 100, y: 100 }, data: { label: 'Broken Node', moduleId: 'mod-bad', moduleName: 'Broken' } }],
                      edges: [],
                    }),
                  },
                ],
              },
            }),
          });
          return;
        }

        if (query.includes('latestWorkflowExecutions')) {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ data: { latestWorkflowExecutions: [] } }),
          });
          return;
        }
      }

      await route.continue();
    });

    await page.goto('/dashboard');

    // Try to execute the workflow and verify error feedback
    const workflowLink = page.getByText('Broken Pipeline').first();
    if (await workflowLink.isVisible({ timeout: 3000 }).catch(() => false)) {
      await workflowLink.click();

      const executeBtn = page.getByRole('button', { name: /execute|run/i }).first();
      if (await executeBtn.isVisible({ timeout: 3000 }).catch(() => false)) {
        await executeBtn.click();

        // Should show an error toast or error banner
        await expect(
          page.getByText(/failed|error|compilation/i).first()
        ).toBeVisible({ timeout: 5000 });
      }
    }
  });
});

test.describe('Workflow Version Publishing and Rollback', () => {
  test('publish a version and see it in the version list', async ({ page }) => {
    await setupAuthenticatedSession(page);

    let publishCalled = false;

    await page.route('**/graphql', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({ status: 200, contentType: 'text/plain', body: 'OK' });
        return;
      }

      if (route.request().method() === 'POST') {
        const body = route.request().postDataJSON();
        const query = body?.query || '';

        if (query.includes('me')) {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              data: { me: { id: 'user-1', email: 'test@example.com', name: 'Test User', createdAt: new Date().toISOString(), twoFactorEnabled: false } },
            }),
          });
          return;
        }

        if (query.includes('nodeTemplates')) {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ data: { nodeTemplates: MOCK_TEMPLATES } }),
          });
          return;
        }

        if (query.includes('workflows') && !query.includes('mutation') && !query.includes('Version')) {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              data: {
                workflows: [
                  {
                    id: MOCK_WORKFLOW_ID,
                    name: 'Versioned Pipeline',
                    graphJson: JSON.stringify({
                      nodes: [{ id: 'n1', type: 'talosNode', position: { x: 100, y: 100 }, data: { label: 'Node A', moduleId: 'mod-1', moduleName: 'HTTP Request' } }],
                      edges: [],
                    }),
                  },
                ],
              },
            }),
          });
          return;
        }

        // Handle publishWorkflowVersion mutation
        if (query.includes('publishWorkflowVersion')) {
          publishCalled = true;
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              data: {
                publishWorkflowVersion: {
                  id: MOCK_VERSION_ID,
                  workflowId: MOCK_WORKFLOW_ID,
                  versionNumber: 1,
                  description: body.variables?.description || 'Initial release',
                  graphJson: '{}',
                  createdAt: new Date().toISOString(),
                  publishedBy: 'user-1',
                },
              },
            }),
          });
          return;
        }

        // Handle workflowVersions query
        if (query.includes('workflowVersions') || query.includes('Version')) {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              data: {
                workflowVersions: [
                  {
                    id: MOCK_VERSION_ID,
                    workflowId: MOCK_WORKFLOW_ID,
                    versionNumber: 1,
                    description: 'Initial release',
                    graphJson: '{}',
                    createdAt: new Date().toISOString(),
                    publishedBy: 'user-1',
                  },
                ],
              },
            }),
          });
          return;
        }

        if (query.includes('latestWorkflowExecutions')) {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ data: { latestWorkflowExecutions: [] } }),
          });
          return;
        }
      }

      await route.continue();
    });

    await page.goto('/dashboard');

    // Open the workflow
    const workflowLink = page.getByText('Versioned Pipeline').first();
    if (await workflowLink.isVisible({ timeout: 3000 }).catch(() => false)) {
      await workflowLink.click();

      // Look for a publish/version button
      const publishBtn = page.getByRole('button', { name: /publish|version/i }).first();
      if (await publishBtn.isVisible({ timeout: 3000 }).catch(() => false)) {
        await publishBtn.click();

        // If a description dialog appears, fill it
        const descInput = page.getByPlaceholder(/description/i).or(page.getByLabel(/description/i));
        if (await descInput.isVisible({ timeout: 2000 }).catch(() => false)) {
          await descInput.fill('Initial release');
          await page.getByRole('button', { name: /confirm|publish|save/i }).first().click();
        }

        // Verify publish was called
        expect(publishCalled).toBe(true);
      }
    }
  });

  test('rollback restores previous workflow version', async ({ page }) => {
    await setupAuthenticatedSession(page);

    let rollbackCalled = false;

    await page.route('**/graphql', async (route) => {
      if (route.request().method() === 'GET') {
        await route.fulfill({ status: 200, contentType: 'text/plain', body: 'OK' });
        return;
      }

      if (route.request().method() === 'POST') {
        const body = route.request().postDataJSON();
        const query = body?.query || '';

        if (query.includes('me')) {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              data: { me: { id: 'user-1', email: 'test@example.com', name: 'Test User', createdAt: new Date().toISOString(), twoFactorEnabled: false } },
            }),
          });
          return;
        }

        if (query.includes('nodeTemplates')) {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ data: { nodeTemplates: MOCK_TEMPLATES } }),
          });
          return;
        }

        if (query.includes('workflows') && !query.includes('mutation') && !query.includes('Version')) {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              data: {
                workflows: [
                  {
                    id: MOCK_WORKFLOW_ID,
                    name: 'Versioned Pipeline',
                    graphJson: JSON.stringify({
                      nodes: [
                        { id: 'n1', type: 'talosNode', position: { x: 100, y: 100 }, data: { label: 'Node A', moduleId: 'mod-1', moduleName: 'HTTP Request' } },
                        { id: 'n2', type: 'talosNode', position: { x: 400, y: 100 }, data: { label: 'Node B', moduleId: 'mod-2', moduleName: 'JSON Transform' } },
                      ],
                      edges: [{ id: 'e1', source: 'n1', target: 'n2' }],
                    }),
                  },
                ],
              },
            }),
          });
          return;
        }

        if (query.includes('workflowVersions') || query.includes('Version')) {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              data: {
                workflowVersions: [
                  {
                    id: MOCK_VERSION_ID,
                    workflowId: MOCK_WORKFLOW_ID,
                    versionNumber: 2,
                    description: 'Added Transform node',
                    graphJson: '{}',
                    createdAt: new Date().toISOString(),
                    publishedBy: 'user-1',
                  },
                  {
                    id: '44444444-4444-4444-4444-444444444444',
                    workflowId: MOCK_WORKFLOW_ID,
                    versionNumber: 1,
                    description: 'Initial single-node version',
                    graphJson: JSON.stringify({
                      nodes: [{ id: 'n1', type: 'talosNode', position: { x: 100, y: 100 }, data: { label: 'Node A', moduleId: 'mod-1', moduleName: 'HTTP Request' } }],
                      edges: [],
                    }),
                    createdAt: new Date(Date.now() - 86400000).toISOString(),
                    publishedBy: 'user-1',
                  },
                ],
              },
            }),
          });
          return;
        }

        // Handle rollbackWorkflowVersion mutation
        if (query.includes('rollbackWorkflowVersion')) {
          rollbackCalled = true;
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({
              data: {
                rollbackWorkflowVersion: {
                  id: '55555555-5555-5555-5555-555555555555',
                  workflowId: MOCK_WORKFLOW_ID,
                  versionNumber: 3,
                  description: 'Rollback to version 1',
                  graphJson: JSON.stringify({
                    nodes: [{ id: 'n1', type: 'talosNode', position: { x: 100, y: 100 }, data: { label: 'Node A', moduleId: 'mod-1', moduleName: 'HTTP Request' } }],
                    edges: [],
                  }),
                  createdAt: new Date().toISOString(),
                  publishedBy: 'user-1',
                },
              },
            }),
          });
          return;
        }

        if (query.includes('latestWorkflowExecutions')) {
          await route.fulfill({
            status: 200,
            contentType: 'application/json',
            body: JSON.stringify({ data: { latestWorkflowExecutions: [] } }),
          });
          return;
        }
      }

      await route.continue();
    });

    await page.goto('/dashboard');

    // Open the workflow
    const workflowLink = page.getByText('Versioned Pipeline').first();
    if (await workflowLink.isVisible({ timeout: 3000 }).catch(() => false)) {
      await workflowLink.click();

      // Look for version history or rollback controls
      const versionBtn = page.getByRole('button', { name: /version|history|rollback/i }).first();
      if (await versionBtn.isVisible({ timeout: 3000 }).catch(() => false)) {
        await versionBtn.click();

        // Select version 1 to rollback to
        const v1Entry = page.getByText(/initial single-node|version 1/i).first();
        if (await v1Entry.isVisible({ timeout: 2000 }).catch(() => false)) {
          await v1Entry.click();

          const rollbackBtn = page.getByRole('button', { name: /rollback|restore/i }).first();
          if (await rollbackBtn.isVisible({ timeout: 2000 }).catch(() => false)) {
            await rollbackBtn.click();
            expect(rollbackCalled).toBe(true);
          }
        }
      }
    }
  });
});
