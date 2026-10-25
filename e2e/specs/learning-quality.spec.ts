import { expect, test } from "../fixtures/test";

test.describe("defensive learning", () => {
  test("runs exploit regressions and persists a completed remediation", async ({ page }) => {
    await page.goto("/#/lab/sqli");
    await page.getByTestId("remediation-tab").click();
    await page.getByRole("radio", { name: /Patch B/ }).click();
    await page.getByRole("button", { name: /攻撃テストを実行/ }).click();

    const results = page.getByTestId("regression-results");
    await expect(results).toContainText("修正完了");
    await expect(results.getByText("BLOCKED")).toHaveCount(4);
    await expect.poll(async () => page.evaluate(() => localStorage.getItem("hacklab.learning.v1"))).toContain("sqli");
  });

  test("shows a labelled real-world CVE example", async ({ page }) => {
    await page.goto("/#/lab/jwt");
    await page.getByRole("tab", { name: "解説" }).click();
    const cves = page.getByTestId("cve-list");
    await expect(cves).toContainText("CVE-2015-9235");
    await expect(cves).toContainText("同じ攻撃メカニズム");
  });
});

test.describe("Harbor chained mission", () => {
  test("keeps later steps locked until evidence is recorded", async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem("hacklab.progress.v1", JSON.stringify({ sqli: [4] })));
    await page.goto("/#/mission");

    const first = page.getByTestId("mission-step-initial-access");
    const second = page.getByTestId("mission-step-mfa-bypass");
    await expect(first).toContainText("証拠あり");
    await expect(second).toContainText("LOCKED");

    await first.getByRole("button", { name: /証拠を記録/ }).click();
    await expect(second).toContainText("調査中");
    await expect(second).toContainText("認証・セッション管理 Lv4");
  });
});

