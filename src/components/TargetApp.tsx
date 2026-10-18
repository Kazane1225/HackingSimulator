import type { ReactNode } from "react";
import type { Progress } from "../progress";
import { worldFromProgress } from "../target/world";

const money = (n: number) => "¥" + n.toLocaleString("ja-JP");

interface Props {
  labId: string;
  /** Attacker-site tab (CSRF kitten page) stays outside this app. */
  browserTab: string;
  progress: Progress;
  children: ReactNode;
}

/**
 * One target application around every lab screen.
 * Cleared work shows up here. The lab currently open keeps its own door,
 * so that strip is left to the screen underneath.
 */
export function TargetApp({ labId, browserTab, progress, children }: Props) {
  if (browserTab === "evil") return <>{children}</>;

  const world = worldFromProgress(progress);
  const showBalance = labId !== "csrf";
  const showOrders = labId !== "idor";
  const showMail = labId !== "auth" && world.mail !== null;
  const showAvatar = labId !== "upload";

  return (
    <div className="target-app" data-testid="target-app">
      <div className="target-bar">
        <div className="target-id">
          {showAvatar && (
            <span
              className={`target-avatar${world.avatarReplaced ? " replaced" : ""}`}
              data-testid="target-avatar"
            >
              {world.avatarReplaced ? "画像" : world.account.slice(0, 1).toUpperCase()}
            </span>
          )}
          <span data-testid="target-account">{world.account}</span>
        </div>
        {showBalance && (
          <span className="target-balance mono" data-testid="target-balance">
            {money(world.balance)}
          </span>
        )}
      </div>
      {showOrders && (
        <ul className="target-orders" data-testid="target-orders">
          {world.orders.map((order) => (
            <li key={order.id}>
              <span className="mono">{order.id}</span>
              <span>{order.item}</span>
              <span>{order.price}</span>
              <span className="mono">{order.card}</span>
            </li>
          ))}
        </ul>
      )}
      {showMail && world.mail && (
        <div className="target-mail" data-testid="target-mail">
          <span>{world.mail.subject}</span>
          <span className="mono">{world.mail.body}</span>
        </div>
      )}
      <div className="target-app-body">{children}</div>
    </div>
  );
}
