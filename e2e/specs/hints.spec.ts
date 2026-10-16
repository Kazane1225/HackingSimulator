import { expect, test } from "../fixtures/test";
import { STATUS } from "../data/labels";
import { HINT_COUNTS, HINT_LAB } from "../data/hints";
import { XSS_EXPLOITS, XSS_PARAM } from "../data/xss";

test.describe("progressive hints", () => {
  test.beforeEach(async ({ lab }) => {
    await lab.goto(HINT_LAB);
  });

  for (const level of [1, 5] as const) {
    test(`Lv${level} reveals hints one at a time (${HINT_COUNTS[level]} in total)`, async ({ lab }) => {
      await lab.selectLevel(level);
      await lab.openInspectorTab("hint");

      await expect(lab.hintItems).toHaveCount(1);
      for (let shown = 2; shown <= HINT_COUNTS[level]; shown++) {
        await lab.nextHintButton.click();
        await expect(lab.hintItems).toHaveCount(shown);
      }
      await expect(lab.nextHintButton).toBeHidden();
    });
  }

  test("hint progress is kept per level", async ({ lab }) => {
    await lab.openInspectorTab("hint");
    await lab.nextHintButton.click();
    await expect(lab.hintItems).toHaveCount(2);

    await lab.selectLevel(2);
    await expect(lab.hintItems).toHaveCount(1);

    await lab.selectLevel(1);
    await expect(lab.hintItems).toHaveCount(2);
  });
});

test.describe("solution unlock", () => {
  test("the solution stays locked until the level is cleared", async ({ lab }) => {
    await lab.goto(HINT_LAB);
    await lab.openInspectorTab("solution");
    await expect(lab.solutionLocked).toBeVisible();

    await lab.send(XSS_PARAM, XSS_EXPLOITS[1].comment);
    await expect(lab.statusBadge).toHaveText(STATUS.success);

    await lab.openInspectorTab("solution");
    await expect(lab.solutionLocked).toBeHidden();
  });
});
