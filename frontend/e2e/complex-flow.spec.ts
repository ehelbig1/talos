import { test, expect } from '@playwright/test';

test.describe('Workflow Flow', () => {
  test('complex workflow with multiple connected nodes', async ({ page }) => {
    // 1. Go to dashboard
    await page.goto('/dashboard');

    // 2. Click "New Workflow" (using the button text directly)
    await page.getByRole('button', { name: /New Workflow/i }).first().click();

    // The current code redirects to /editor
    await expect(page).toHaveURL(/\/editor/);

    // 3. Add HTTP Node
    await page.getByRole('button', { name: /add node/i }).click();
    await page.getByText(/http request/i).first().click();

    // Fill node name (using the label we fixed earlier)
    await page.getByLabel(/node name/i).fill('Fetcher');
    await page.getByRole('button', { name: /create node/i }).click();

    // 4. Add Transform Node
    await page.getByRole('button', { name: /add node/i }).click();
    await page.getByText(/json transform/i).first().click();
    await page.getByLabel(/node name/i).fill('Transformer');
    await page.getByRole('button', { name: /create node/i }).click();

    // 5. Verify they both exist in the view
    await expect(page.getByText('Fetcher')).toBeVisible();
    await expect(page.getByText('Transformer')).toBeVisible();

    // 6. Save Workflow
    await page.getByRole('button', { name: /save/i }).click();
    // Assuming a success toast appears
    await expect(page.getByText(/saved/i)).toBeVisible();

    // 7. Execute Workflow
    await page.getByRole('button', { name: /execute/i }).click();

    // 8. Verify Execution History
    await page.getByRole('button', { name: /history/i }).click();
    await expect(page.getByText('completed').first()).toBeVisible();
  });
});
