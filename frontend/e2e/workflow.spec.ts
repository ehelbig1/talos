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

/** Standard mock responses for me, nodeTemplates, and latestWorkflowExecutions. */
async function setupGraphQLMock(page: import('@playwright/test').Page) {
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
    console.log(`E2E MOCK: Intercepted GraphQL query: ${query.substring(0, 50)}...`);

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

    // workflows (empty list for smoke test)
    if (query.match(/\{\s*workflows\b/i) && !query.includes('mutation')) {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ data: { workflows: [] } }),
      });
      return;
    }

    // pendingApprovals
    if (query.includes('pendingApprovals')) {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ data: { pendingApprovals: [] } }),
      });
      return;
    }

    // nodeTemplates
    if (query.match(/\{\s*nodeTemplates\b/i)) {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: {
            nodeTemplates: [
              {
                id: 'tpl-echo',
                name: 'Echo',
                category: 'utility',
                configSchema: '{}',
                codeTemplate: '',
                capabilityWorld: 'echo',
                description: 'Echo input to output',
                icon: null,
                allowedHosts: [],
              },
            ],
          },
        }),
      });
      return;
    }

    // createWorkflow mutation
    if (query.includes('createWorkflow')) {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: {
            createWorkflow: {
              id: 'new-workflow-id',
              name: 'New Workflow',
              graphJson: '{}',
            },
          },
        }),
      });
      return;
    }

    // createModuleFromTemplate mutation
    if (query.includes('createModuleFromTemplate')) {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: {
            createModuleFromTemplate: {
              id: 'new-module-id',
              name: body.variables.input.name || 'Mock Node',
            },
          },
        }),
      });
      return;
    }

    // createWorkflow mutation
    if (query.includes('createWorkflow')) {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: {
            createWorkflow: {
              id: 'new-workflow-id',
              name: body.variables.input.name || 'New Workflow',
            },
          },
        }),
      });
      return;
    }

    // updateWorkflow mutation

    await route.continue();
  });
}

test('basic workflow creation smoke test', async ({ page }) => {
  test.setTimeout(120000);
  
  // Log browser console messages
  page.on('console', msg => console.log(`BROWSER CONSOLE: ${msg.type()}: ${msg.text()}`));
  page.on('pageerror', err => console.log(`BROWSER ERROR: ${err.message}`));

  // 0. Setup session and mocks
  await setupAuthenticatedSession(page);
  await setupGraphQLMock(page);

  // 1. Visit the dashboard
  console.log('Navigating to /dashboard');
  await page.goto('/dashboard');
  await page.waitForLoadState('networkidle');

  // 2. Click "+ New Workflow"
  console.log('Clicking New Workflow');
  await page.getByRole('button', { name: /\+ New Workflow/i }).click();

  // 3. Verify we are in the editor
  console.log('Current URL:', page.url());
  await expect(page).toHaveURL(/\/editor/);
  await page.waitForLoadState('networkidle');

  // 4. Open "New Module" dialog
  console.log('Waiting for New Module button');
  const newModuleBtn = page.getByRole('button', { name: /new module/i });
  try {
    await expect(newModuleBtn).toBeVisible({ timeout: 20000 });
  } catch (e) {
    console.log('New Module button not found. Dumping page content:');
    console.log(await page.content());
    throw e;
  }
  await newModuleBtn.click();

  // 5. Select a template (e.g., Echo)
  console.log('Selecting Echo template');
  const echoTemplate = page.getByText(/echo/i).first();
  try {
    await expect(echoTemplate).toBeVisible({ timeout: 10000 });
  } catch (e) {
    console.log('Echo template not found in dialog. Dumping page content and screenshot:');
    await page.screenshot({ path: 'test-results/echo-not-found.png' });
    console.log(await page.content());
    throw e;
  }
  await echoTemplate.click({ force: true });

  // 6. Name the node
  console.log('Naming node');
  await page.getByPlaceholder(/notify-slack-channel/i).fill('Test Echo Node');

  // 7. Create the node
  console.log('Clicking Create Node');
  await page.getByRole('button', { name: /create node/i }).click();

  // 8. Verify node appears in workspace
  console.log('Verifying node in workspace');
  await expect(page.locator('.react-flow__node-talosNode')).toBeVisible();
  await expect(page.getByText('Test Echo Node')).toBeVisible();

  // 9. Save workflow
  const saveBtn = page.getByRole('button', { name: /save/i }).filter({ hasText: /^save$/i }).filter({ visible: true });
  await expect(saveBtn).toBeEnabled({ timeout: 15000 });
  await saveBtn.click();

  // 9a. Handle naming dialog if it's a new workflow
  const nameDialogHeader = page.getByRole('heading', { name: /name your workflow/i }).first();
  try {
    if (await nameDialogHeader.isVisible({ timeout: 5000 })) {
      await page.getByPlaceholder(/enter workflow name/i).fill('My E2E Workflow');
      await page.getByRole('button', { name: /^save$/i }).filter({ visible: true }).click();
    }
  } catch (e) {
    // Dialog didn't appear, likely already has a name or failed to trigger
  }
  
  // 10. Verify success toast or redirect
  await expect(page.getByText(/workflow saved/i)).toBeVisible({ timeout: 20000 });
});
