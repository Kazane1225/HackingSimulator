import type { Page } from "@playwright/test";
import { STORAGE_KEY } from "../data/progress";

/** Read the saved progress straight from localStorage ({} when nothing is stored). */
export async function readProgress(page: Page): Promise<unknown> {
  const raw = await page.evaluate((key) => localStorage.getItem(key), STORAGE_KEY);
  return raw === null ? {} : JSON.parse(raw);
}

/** Pre-seed localStorage before the app loads (runs on every navigation). */
export async function seedProgress(page: Page, raw: string) {
  await page.addInitScript(([key, value]) => localStorage.setItem(key, value), [STORAGE_KEY, raw]);
}
