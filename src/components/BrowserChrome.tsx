import type { ReactNode } from "react";
import { Lock, Reload } from "./icons";

export interface BrowserTab {
  id: string;
  url: string;
  title: string;
}

interface Props {
  tabs: BrowserTab[];
  activeTabId: string;
  onTabChange: (id: string) => void;
  children: ReactNode;
  onReload?: () => void;
}

/** A faux browser window that frames a simulated target application. */
export function BrowserChrome({ tabs, activeTabId, onTabChange, children, onReload }: Props) {
  const active = tabs.find((t) => t.id === activeTabId) ?? tabs[0];

  return (
    <div className="browser">
      <div className="browser-topbar">
        <span className="traffic">
          <i className="tl-red" />
          <i className="tl-amber" />
          <i className="tl-green" />
        </span>
        <div className="tabs" role="tablist" aria-label="ブラウザのタブ">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              type="button"
              role="tab"
              aria-selected={tab.id === active.id}
              className={`tab ${tab.id === active.id ? "active" : ""}`}
              onClick={() => onTabChange(tab.id)}
            >
              {tab.title}
            </button>
          ))}
        </div>
      </div>
      <div className="browser-omnibar">
        <button
          className="omni-btn"
          onClick={onReload}
          title="再読み込み"
          type="button"
          disabled={!onReload}
        >
          <Reload width={15} height={15} />
        </button>
        <div className="omnibox">
          <Lock width={13} height={13} className="omni-lock" />
          <span className="omni-url">{active.url}</span>
        </div>
      </div>
      <div className="browser-viewport">{children}</div>
    </div>
  );
}
