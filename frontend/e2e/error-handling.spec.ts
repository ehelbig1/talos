import { test, expect, Page } from '@playwright/test';

async function setupAuthenticatedSession(page: Page) {
  await page.context().addCookies([
    { name: 'talos_access_token', value: 'mock-token', domain: 'localhost', path: '/' },
    { name: 'talos_csrf', value: 'mock-csrf', domain: 'localhost', path: '/' },
  ]);
}

async function setupErrorMocks(page: Page) {
  await page.route('**/graphql', async (route) => {
    const body = route.request().postDataJSON();
    const query = body?.query || '';

    if (query.match(/\{\s*me\b/i)) {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ data: { me: { id: 'u1', email: 't@e.com', name: 'T' } } }),
      });
      return;
    }

    if (query.includes('query GetWorkflow')) {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          data: {
            workflow: {
              id: body.variables.id,
              name: 'Error Test Workflow',
              graphJson: JSON.stringify({
                nodes: [
                  {
                    id: '1',
                    type: 'talosNode',
                    position: { x: 100, y: 100 },
                    data: {
                      label: 'Error Node',
                      type: '00000000-0000-0000-0000-000000000000', // Valid UUID
                      category: 'utility',
                      executionStatus: 'failed',
                      lastError: 'Simulated error for testing',
                      fixProposal: 'Try increasing the timeout or checking the input payload format.',
                    },
                  },
                ],
                edges: [],
              }),
            },
          },
        }),
      });
      return;
    }

    await route.continue();
  });
}

test.describe('Node Error Handling & Interaction', () => {
  test.beforeEach(async ({ page }) => {
    await setupAuthenticatedSession(page);
    await setupErrorMocks(page);
  });

  test('should display error overlay and fix suggestion for failed nodes', async ({ page }) => {
    await page.goto('/editor/error-test-id');
    await page.waitForLoadState('networkidle');

    const node = page.locator('[data-id="1"]');
    await expect(node).toBeVisible();

    // Check for error status indicator (failed border/shadow)
    // The actual indicator is on the container div
    await expect(node).toHaveClass(/ring-2/);

    // Check for error message display
    await expect(page.getByText('Simulated error for testing')).toBeVisible();
    
    // Check for fix suggestion
    await expect(page.getByText('PROPOSAL: Try increasing the timeout')).toBeVisible();
  });

  test('should support keyboard shortcuts for node management', async ({ page }) => {
    await page.goto('/editor/error-test-id');
    await page.waitForLoadState('networkidle');

    const node = page.locator('[data-id="1"]');
    await node.click(); // Focus the node
    await expect(node).toHaveClass(/selected/);

    // Test Duplication (Cmd+D or Ctrl+D)
    // We'll use the specific shortcut we implemented
    const isMac = process.platform === 'darwin';
    const modifier = isMac ? 'Meta' : 'Control';
    await page.keyboard.press(`${modifier}+d`);

    // Verify duplication (should have 2 nodes now)
    await expect(page.locator('.react-flow__node-talosNode')).toHaveCount(2);

    // Test Deletion
    await page.keyboard.press('Delete');
    // After delete, the selected node should be gone
    await expect(page.locator('.react-flow__node-talosNode')).toHaveCount(1);
    
    // Test Backspace deletion (common alias)
    await page.locator('.react-flow__node-talosNode').first().click();
    await page.keyboard.press('Backspace');
    await expect(page.locator('.react-flow__node-talosNode')).toHaveCount(0);
  });
});
