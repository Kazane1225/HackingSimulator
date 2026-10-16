import { expect, test } from "../fixtures/test";
import { STATUS } from "../data/labels";
import { CORRUPTED_STORAGE } from "../data/progress";
import { XSS_EXPLOITS, XSS_PARAM } from "../data/xss";
import { readProgress, seedProgress } from "../support/storage";

test.describe("progress persistence", () => {
  test("a cleared level is saved and survives a reload", async ({ lab, sidebar, page }) => {
    await lab.goto("xss");
    await lab.send(XSS_PARAM, XSS_EXPLOITS[1].comment);
    await expect(lab.statusBadge).toHaveText(STATUS.success);
    await expect(sidebar.labLink("xss", 1)).toBeVisible();

    await page.reload();

    await expect(sidebar.labLink("xss", 1)).toBeVisible();
    expect(await readProgress(page)).toEqual({ xss: [1] });
    // The lab reopens on the first level that is still unsolved.
    await expect(lab.levelTab(2)).toHaveAttribute("aria-selected", "true");
  });

  for (const { name, raw, expected } of CORRUPTED_STORAGE) {
    test(`recovers from corrupted storage: ${name}`, async ({ page, sidebar }) => {
      await seedProgress(page, raw);
      await page.goto("/#/");

      await expect(page.getByRole("heading", { name: "ダッシュボード" })).toBeVisible();
      for (const [labId, cleared] of Object.entries(expected)) {
        await expect(sidebar.labLink(labId, cleared)).toBeVisible();
      }
    });
  }
});
