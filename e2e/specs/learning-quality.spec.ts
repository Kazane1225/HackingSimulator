import type { Page } from "@playwright/test";
import { expect, test } from "../fixtures/test";

const PATCHES = ["A", "B", "C", "D"];

async function openRemediation(page: Page, labId: string, cleared: number[]) {
  await page.addInitScript(
    ([id, levels]) => localStorage.setItem("hacklab.progress.v1", JSON.stringify({ [id as string]: levels })),
    [labId, cleared] as const,
  );
  await page.goto(`/#/lab/${labId}`);
  await page.getByTestId("remediation-tab").click();
}

async function predictAllBlocked(page: Page) {
  for (const lv of [1, 2, 3, 4]) {
    await page.getByRole("radiogroup", { name: `Lv${lv} の攻撃の予想` }).getByRole("radio", { name: "防ぐ" }).click();
  }
}

test.describe("defensive learning", () => {
  test("requires a prediction before the regression run", async ({ page }) => {
    await openRemediation(page, "sqli", [1, 2, 3, 4]);
    const run = page.getByRole("button", { name: /攻撃テストを実行/ });
    await expect(run).toBeDisabled();
    await page.getByRole("radio", { name: /^Patch A/ }).click();
    await expect(run).toBeDisabled();
    await predictAllBlocked(page);
    await expect(run).toBeEnabled();
  });

  test("exactly one patch survives, and failures explain the breach", async ({ page }) => {
    await openRemediation(page, "sqli", [1, 2, 3, 4]);
    const results = page.getByTestId("regression-results");
    let secure = 0;
    for (const patch of PATCHES) {
      await page.getByRole("radio", { name: new RegExp(`^Patch ${patch}`) }).click();
      await predictAllBlocked(page);
      await page.getByRole("button", { name: /攻撃テストを実行/ }).click();
      await expect(results).toContainText("予想の的中");
      if ((await results.getByText("修正完了").count()) > 0) {
        secure++;
        await expect(results.getByText("BLOCKED")).toHaveCount(4);
        await expect(page.getByTestId("breach")).toHaveCount(0);
      } else {
        await expect(results).toContainText("回帰テスト失敗");
        await expect(page.getByTestId("breach").first()).toContainText("サーバーが組み立てた処理");
        await expect(results).toContainText("なぜ破られたか");
      }
    }
    expect(secure).toBe(1);
    await expect(page.getByTestId("answer-key")).toContainText("既知の攻撃をすべて防ぐ");
    await expect.poll(async () => page.evaluate(() => localStorage.getItem("hacklab.learning.v1"))).toContain("sqli");
  });

  test("hides the attack details for levels the learner has not cleared", async ({ page }) => {
    await openRemediation(page, "sqli", []);
    const results = page.getByTestId("regression-results");
    for (const patch of PATCHES) {
      await page.getByRole("radio", { name: new RegExp(`^Patch ${patch}`) }).click();
      await predictAllBlocked(page);
      await page.getByRole("button", { name: /攻撃テストを実行/ }).click();
      if ((await results.getByText("回帰テスト失敗").count()) > 0) {
        await expect(page.getByTestId("breach").first()).toContainText("クリアすると");
        await expect(page.getByTestId("breach").first()).not.toContainText("サーバーが組み立てた処理");
        await expect(results).not.toContainText("なぜ破られたか");
        return;
      }
    }
    throw new Error("no failing patch found");
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

