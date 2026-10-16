import { expect, test } from "../fixtures/test";
import { STATUS } from "../data/labels";
import { XSS_EXPLOITS, XSS_NON_EXECUTING, XSS_PARAM } from "../data/xss";
import { readProgress } from "../support/storage";

test.describe("XSS lab: clear is judged by real execution in the sandbox", () => {
  test.beforeEach(async ({ lab }) => {
    await lab.goto("xss");
  });

  for (const level of [1, 2, 3, 4] as const) {
    test(`Lv${level} reference exploit fires and clears the level`, async ({ lab, page }) => {
      await lab.selectLevel(level);
      await lab.send(XSS_PARAM, XSS_EXPLOITS[level].comment);

      await expect(lab.statusBadge).toHaveText(STATUS.success);
      expect(await readProgress(page)).toEqual({ xss: [level] });
    });
  }

  for (const { level, payload, reason } of XSS_NON_EXECUTING) {
    test(`Lv${level} payload that never executes is not credited (${reason})`, async ({ lab, page }) => {
      await lab.selectLevel(level);
      await lab.send(XSS_PARAM, payload);
      await lab.waitForPreviewSettled();

      await expect(lab.statusBadge).toHaveText(STATUS.failure);
      expect(await readProgress(page)).toEqual({});
    });
  }

  test("Lv5 neutralizes the Lv4 exploit", async ({ lab, page }) => {
    await lab.selectLevel(5);
    await lab.send(XSS_PARAM, XSS_EXPLOITS[4].comment);
    await lab.waitForPreviewSettled();

    await expect(lab.statusBadge).toHaveText(STATUS.blocked);
    expect(await readProgress(page)).toEqual({});
  });
});

