import type { Page } from "@playwright/test";

/** Pixels by which the page is wider than the viewport (0 or less is fine). */
export function horizontalOverflow(page: Page): Promise<number> {
  return page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
}
