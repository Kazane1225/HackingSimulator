import { test as base } from "@playwright/test";
import { LabPage } from "../pages/LabPage";
import { Sidebar } from "../pages/Sidebar";
import { SqliLoginApp } from "../pages/apps/SqliLoginApp";

interface Fixtures {
  lab: LabPage;
  sidebar: Sidebar;
  sqliApp: SqliLoginApp;
}

export const test = base.extend<Fixtures>({
  lab: async ({ page }, use) => use(new LabPage(page)),
  sidebar: async ({ page }, use) => use(new Sidebar(page)),
  sqliApp: async ({ lab }, use) => use(new SqliLoginApp(lab)),
});

export { expect } from "@playwright/test";
