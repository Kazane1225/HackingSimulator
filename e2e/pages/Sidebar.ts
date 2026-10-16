import type { Locator, Page } from "@playwright/test";
import { LAB_TITLES } from "../data/labels";

/** Lab navigation (side panel on desktop, tab strip on phones). */
export class Sidebar {
  constructor(private readonly page: Page) {}

  /** The lab link, which exposes the cleared-level count in its name. */
  labLink(labId: string, cleared?: number): Locator {
    const title = LAB_TITLES[labId];
    const name = cleared === undefined ? new RegExp(`^${title} \\d / 4 クリア$`) : `${title} ${cleared} / 4 クリア`;
    return this.page.getByRole("link", { name });
  }

  glossaryLink(): Locator {
    return this.page.getByRole("link", { name: "用語集", exact: true });
  }
}
