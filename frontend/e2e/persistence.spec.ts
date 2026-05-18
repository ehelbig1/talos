import { test, expect, Page } from '@playwright/test';

/**
 * Helper: set up a mocked authenticated session with auth + CSRF cookies.
 */
async function setupAuthenticatedSession(page: Page) {
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

/** Standard mock responses for me, nodeTemplates, and latestWorkflowExecutions. */
async function setupGraphQLMock(page: import('@playwright/test').Page) {
  // We'll store the "saved" workflow state here for the duration of the test run to simulate persistence
  let savedWorkflow: any = null;

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

    // me
    if (query.match(/\{\s*me\b/i)) {
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

    // GetWorkflow
    if (query.includes('query GetWorkflow')) {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: {
            workflow: savedWorkflow || {
              id: body.variables.id,
              name: 'Mock Workflow',
              graphJson: JSON.stringify({ nodes: [], edges: [] }),
            }
          }
        })
      });
      return;
    }

    // GetModules / wasmModules
    if (query.includes('query GetModules') || query.includes('wasmModules')) {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: {
            wasmModules: [
              { 
                id: '00000000-0000-0000-0000-000000000001', 
                name: 'Echo', 
                config: '{}',
                capabilityWorld: 'standard',
                importedInterfaces: []
              }
            ]
          }
        })
      });
      return;
    }

    // workflows list
    if (query.match(/\{\s*workflows\b/i) && !query.includes('mutation')) {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ 
          data: { 
            workflows: savedWorkflow ? [savedWorkflow] : [] 
          } 
        }),
      });
      return;
    }

    // createWorkflow mutation
    if (query.includes('createWorkflow')) {
      savedWorkflow = {
        id: '11111111-1111-1111-1111-111111111111',
        name: body.variables.input.name || 'New Workflow',
        graphJson: body.variables.input.graphJson,
      };
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: {
            createWorkflow: savedWorkflow,
          },
        }),
      });
      return;
    }

    // updateWorkflow mutation
    if (query.includes('updateWorkflow')) {
      savedWorkflow = {
        id: body.variables.id,
        name: body.variables.input.name,
        graphJson: body.variables.input.graphJson,
      };
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: {
            updateWorkflow: savedWorkflow,
          },
        }),
      });
      return;
    }

    // myModules (for dashboard if needed)
    if (query.includes('myModules')) {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: {
            myModules: [
              { 
                id: '00000000-0000-0000-0000-000000000001', 
                name: 'Echo', 
                sizeBytes: 1024 * 1024, 
                contentHash: 'abc', 
                compiledAt: new Date().toISOString(), 
                config: '{}',
                capabilityWorld: 'standard',
                capabilityDescription: 'A simple echo module',
                importedInterfaces: []
              }
            ]
          }
        })
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

test.describe('Workflow Persistence', () => {
  test('should create, save, and reload a workflow', async ({ page }) => {
    // 0. Setup authentication and mocks
    await setupAuthenticatedSession(page);
    await setupGraphQLMock(page);

    await page.goto('/dashboard');
    await page.waitForLoadState('networkidle');

    // Enter editor
    await page.getByRole('button', { name: /\+ New Workflow/i }).click();
    await expect(page).toHaveURL(/\/editor/);

    // 1. Add a module from library
    await page.getByLabel('Open module library').click();
    await page.locator('div.group.cursor-pointer').filter({ hasText: 'Echo' }).click();
    await page.getByRole('button', { name: 'Add Node' }).click();
    
    const node = page.locator('.react-flow__node-talosNode');
    await expect(node).toBeVisible();

    // 2. Add a control flow node
    await page.getByLabel('Open control flow menu').click();
    await page.getByRole('menuitem', { name: 'For Each' }).click();
    
    await expect(page.locator('.react-flow__node-talosNode')).toHaveCount(2);

    // 3. Save the workflow
    await page.getByRole('button', { name: 'Save', exact: true }).filter({ hasNotText: 'Saving' }).click();

    // 4. Handle Save Name Dialog
    await expect(page.getByRole('heading', { name: 'Name Your Workflow' }).first()).toBeVisible();
    const workflowName = `Test Workflow ${Date.now()}`;
    await page.getByPlaceholder('Enter workflow name').fill(workflowName);
    await page.getByRole('dialog').getByRole('button', { name: 'Save', exact: true }).click();

    await expect(page.getByText('Workflow saved')).toBeVisible();

    // 5. Reload via Dashboard and verify
    // We go to dashboard to ensure the workflow list fetches our newly saved workflow
    await page.goto('/dashboard');
    await expect(page.getByText(workflowName)).toBeVisible();

    // Re-edit the workflow
    const card = page.locator('.glass-card', { hasText: workflowName });
    await card.getByRole('button', { name: /Edit/i }).click();
    
    await expect(page).toHaveURL(/\/editor/);
    
    // Verify nodes are reloaded
    await expect(page.locator('.react-flow__node-talosNode')).toHaveCount(2);
  });
});

