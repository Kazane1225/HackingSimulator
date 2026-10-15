import type { ReactNode } from "react";
import { Lock, Reload } from "./icons";

interface Props {
  url: string;
  title: string;
  children: ReactNode;
  onReload?: () => void;
  /** Optional second tab (used by the CSRF lab for the attacker's page). */
  secondTab?: string;
}

/** A faux browser window that frames a simulated target application. */
export function BrowserChrome({ url, title, children, onReload, secondTab }: Props) {
  return (
    <div className="browser">
      <div className="browser-topbar">
        <span className="traffic">
          <i className="tl-red" />
          <i className="tl-amber" />
          <i className="tl-green" />
        </span>
        <div className="tabs">
          <span className="tab active">{title}</span>
          {secondTab && <span className="tab">{secondTab}</span>}
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
          <span className="omni-url">{url}</span>
        </div>
      </div>
      <div className="browser-viewport">{children}</div>
    </div>
  );
}
