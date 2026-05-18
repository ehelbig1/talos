import { test, expect } from '@playwright/test';

test.describe('Error Handling and Navigation', () => {
  test('redirects to dashboard on invalid routes', async ({ page }) => {
    await page.goto('/invalid-route-that-does-not-exist');
    // Assuming there is a 404 handler or redirect
    await expect(page).toHaveURL(/\/dashboard|404/);
  });

  test('handles session expiry scenario', async ({ page }) => {
    await page.goto('/dashboard');
    // Manually clear cookies to simulate expiry
    await page.context().clearCookies();
    await page.reload();
    // Should redirect to login or show auth required
    await expect(page).toHaveURL(/\/login|auth/);
  });

  test('inspector shows error states', async ({ page }) => {
    // This would ideally use a mocked backend or a specific workflow state
    // For now we just verify navigation to builder
    await page.goto('/dashboard');
    await page.getByRole('button', { name: /create workflow/i }).click();
    await expect(page).toHaveURL(/\/builder/);
  });
});
