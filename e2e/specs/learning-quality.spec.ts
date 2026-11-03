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
    await expect(second).toContainText("認証 / Session の Lv4");
    await expect(second).toContainText("MFA コード");
    await expect(second).not.toContainText("auth-mfa");
  });

  test("opens the required level and carries the stolen password", async ({ page, lab }) => {
    await page.addInitScript(() => {
      localStorage.setItem("hacklab.progress.v1", JSON.stringify({ sqli: [4] }));
      localStorage.setItem("hacklab.learning.v1", JSON.stringify({ remediatedLabIds: [], completedMissionStepIds: ["initial-access"] }));
      localStorage.setItem(
        "hacklab.loot.v2",
        JSON.stringify([{ id: "sqli-pass-admin", label: "admin のパスワード", value: "S3cr3t-Pa55!", labId: "sqli" }]),
      );
    });
    await page.goto("/#/lab/auth?lv=4");
    await page.goto("/#/mission");
    await page.getByTestId("mission-step-mfa-bypass").getByRole("link", { name: /対象ラボを開く/ }).click();
    await expect(page).toHaveURL(/#\/lab\/auth\?lv=4&from=mission$/);
    await expect(lab.levelTab(4)).toHaveAttribute("aria-selected", "true");
    await expect(page.getByTestId("carry-note")).toContainText("持ち込んだ情報");
    await expect(lab.proxyParam("username")).toHaveValue("guest");
    await expect(lab.proxyParam("password")).toHaveValue("guest");
    await lab.proxyParam("password").click();
    await page.getByTestId("carried-loot").getByRole("button", { name: /S3cr3t-Pa55!/ }).click();
    await expect(lab.proxyParam("password")).toHaveValue("S3cr3t-Pa55!");
  });
});

test.describe("workbench continuity", () => {
  test("keeps the proxy draft when the level changes", async ({ lab }) => {
    await lab.goto("sqli");
    await lab.setParam("username", "alice'--");
    await lab.selectLevel(2);
    await expect(lab.proxyParam("username")).toHaveValue("alice'--");
    await lab.setParam("username", "bob");
    await lab.selectLevel(1);
    await expect(lab.proxyParam("username")).toHaveValue("alice'--");
    await lab.selectLevel(2);
    await expect(lab.proxyParam("username")).toHaveValue("bob");
  });

  test("restores an earlier request and shows what changed", async ({ lab }) => {
    await lab.goto("sqli");
    await lab.send("username", "one");
    await lab.send("username", "two");
    const history = lab.pane("proxy").getByTestId("request-history");
    await expect(history.getByRole("button")).toHaveCount(2);
    await history.getByRole("checkbox").nth(0).check();
    await history.getByRole("checkbox").nth(1).check();
    await expect(lab.pane("proxy").getByTestId("request-diff")).toContainText("username");
    await history.getByRole("button", { name: /username=one/ }).click();
    await expect(lab.proxyParam("username")).toHaveValue("one");
  });

  test("reset clears loot as well as progress", async ({ page }) => {
    await page.addInitScript(() => {
      localStorage.setItem("hacklab.progress.v1", JSON.stringify({ sqli: [1] }));
      localStorage.setItem(
        "hacklab.loot.v2",
        JSON.stringify([{ id: "auth-mfa", label: "MFA コード", value: "482016", labId: "auth" }]),
      );
    });
    await page.goto("/#/");
    await page.getByRole("button", { name: "進捗をリセット" }).click();
    await page.getByRole("button", { name: "リセットする" }).click();
    await expect.poll(async () => page.evaluate(() => localStorage.getItem("hacklab.progress.v1"))).toBe("{}");
    await expect.poll(async () => page.evaluate(() => localStorage.getItem("hacklab.loot.v2"))).toBe("[]");
  });
});

