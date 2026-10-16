import { expect, test } from "../fixtures/test";
import { STATUS } from "../data/labels";

test.describe("CSRF browser tabs", () => {
  test("starts on the bank tab and keeps the trap page on another tab", async ({ lab }) => {
    await lab.goto("csrf");

    const chrome = lab.pane("target");
    await expect(chrome.getByRole("tab", { name: "SecureBank" })).toHaveAttribute("aria-selected", "true");
    await expect(chrome.getByText("https://bank.example/account")).toBeVisible();
    await expect(chrome.getByText("victim としてログイン中")).toBeVisible();
    await expect(chrome.getByLabel("罠ページの HTML")).toHaveCount(0);

    await chrome.getByRole("tab", { name: "かわいい子猫" }).click();
    await expect(chrome.getByRole("tab", { name: "かわいい子猫" })).toHaveAttribute("aria-selected", "true");
    await expect(chrome.getByText("https://evil.example/cute-kittens")).toBeVisible();
    await expect(chrome.getByLabel("罠ページの HTML")).toBeVisible();
  });

  test("opening the trap page switches back to the bank tab", async ({ page, lab }) => {
    await lab.goto("csrf");
    await lab.setIntercept(false);
    await lab.pane("target").getByRole("tab", { name: "かわいい子猫" }).click();
    await page.getByLabel("罠ページの HTML").fill(
      '<img src="https://bank.example/transfer?to=attacker&amount=10000">',
    );
    await page.getByRole("button", { name: "被害者がこのページを開く" }).click();

    await expect(lab.statusBadge).toHaveText(STATUS.success);
    await expect(lab.pane("target").getByRole("tab", { name: "SecureBank" })).toHaveAttribute("aria-selected", "true");
    await expect(lab.pane("target").getByText(/attacker へ送金されました/)).toBeVisible();
  });
});
