import { test, expect } from '@playwright/test';

test('handling graphql 500 errors', async ({ page }) => {
  // Mock a 500 error for workflow templates
  await page.route('**/graphql', async (route) => {
    if (route.request().method() === 'POST') {
      const body = route.request().postDataJSON();
      if (body && body.query && body.query.includes('nodeTemplates')) {
        await route.fulfill({
          status: 500,
          contentType: 'application/json',
          body: JSON.stringify({ errors: [{ message: 'Internal Server Error' }] }),
        });
        return;
      }
    }
    await route.continue();
  });

  await page.goto('/');
  await page.getByRole('button', { name: /New Workflow/i }).first().click();
  await page.getByRole('button', { name: /Browse Templates/i }).click();

  // Verify ErrorBanner or toast shows up
  await expect(page.getByText(/internal server error/i)).toBeVisible();
});

test('session expiry redirect', async ({ page }) => {
  // Mock a 401 Unauthorized for any request
  await page.route('**/graphql', async (route) => {
    if (route.request().method() === 'POST') {
      await route.fulfill({
        status: 401,
        contentType: 'application/json',
        body: JSON.stringify({ errors: [{ message: 'Authentication required' }] }),
      });
    } else {
      await route.continue();
    }
  });

  await page.goto('/dashboard');

  // Verify it stays on dashboard but shows auth form (since it's not a real redirect but conditional rendering)
  await expect(page.getByRole('button', { name: /Login/i }).first()).toBeVisible();
});
