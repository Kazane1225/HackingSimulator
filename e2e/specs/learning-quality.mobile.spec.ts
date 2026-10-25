import { expect, test } from "../fixtures/test";

test("learning views fit a mobile viewport", async ({ page }) => {
  await page.goto("/#/lab/xss");
  await page.getByTestId("remediation-tab").click();
  await expect(page.getByTestId("remediation-panel")).toBeVisible();
  await expect.poll(async () => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);

  await page.goto("/#/mission");
  await expect(page.getByTestId("mission-step-initial-access")).toBeVisible();
  await expect.poll(async () => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});

