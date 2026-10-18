import { useEffect, useRef, useState } from "react";
import { findLab } from "../labs";
import type { LabInput, Level } from "../labs/types";
import type { Progress } from "../progress";
import { worldFromProgress } from "../target/world";
import { HarborMark, HARBOR_FAVICON, HomeIcon, MailIcon, OrdersIcon, ScreenIcon } from "../target/icons";
import { targetChannel, type TargetState } from "../target/link";
import { LAB_UI } from "./labUI";

type View = "home" | "orders" | "mail" | "tool";

const money = (n: number) => "¥" + n.toLocaleString("ja-JP");

interface Props {
  progress: Progress;
}

function useHarborIdentity(): void {
  useEffect(() => {
    const previousTitle = document.title;
    document.title = "Harbor";
    const link = document.querySelector<HTMLLinkElement>("link[rel='icon'][type='image/svg+xml']");
    const previousHref = link?.getAttribute("href");
    if (link) link.href = `data:image/svg+xml,${encodeURIComponent(HARBOR_FAVICON)}`;
    return () => {
      document.title = previousTitle;
      if (link && previousHref) link.href = previousHref;
    };
  }, []);
}

/** The customer app, opened in its own tab. The workbench stays the other window. */
export function StoreWindow({ progress }: Props) {
  useHarborIdentity();
  const world = worldFromProgress(progress);
  const [view, setView] = useState<View>("home");
  const [remote, setRemote] = useState<TargetState | null>(null);
  const [inputs, setInputs] = useState<LabInput>({});

  const seenLab = useRef<string | null>(null);

  useEffect(() => {
    const channel = targetChannel();
    if (!channel) return;
    channel.onmessage = (ev: MessageEvent<TargetState>) => {
      const msg = ev.data;
      if (!msg || msg.type !== "state") return;
      setRemote(msg);
      setInputs(msg.inputs);
      if (msg.labId !== seenLab.current) {
        seenLab.current = msg.labId;
        setView("tool");
      }
    };
    channel.postMessage({ type: "hello" });
    return () => channel.close();
  }, []);

  const post = (message: { type: string; name?: string; value?: string; patch?: LabInput; id?: string; message?: string }) => {
    const channel = targetChannel();
    channel?.postMessage(message);
    channel?.close();
  };

  const lab = remote ? findLab(remote.labId) : undefined;
  const ui = remote ? LAB_UI[remote.labId] : undefined;

  const setField = (name: string, value: string) => {
    setInputs((prev) => ({ ...prev, [name]: value }));
    post({ type: "field", name, value });
  };

  const pageTitle = view === "home" ? "ホーム" : view === "orders" ? "注文" : view === "mail" ? "受信箱" : (ui?.site ?? "画面");

  return (
    <div className="store" data-testid="store-window">
      <aside className="store-nav">
        <div className="store-brand">
          <span className="store-logo">
            <HarborMark width={18} height={18} />
          </span>
          <span>
            <strong>Harbor</strong>
            <small>アカウント</small>
          </span>
        </div>
        <nav className="store-nav-list">
          <button type="button" className={view === "home" ? "active" : ""} aria-label="ホーム" onClick={() => setView("home")}>
            <HomeIcon width={18} height={18} />
            <span>ホーム</span>
          </button>
          <button type="button" className={view === "orders" ? "active" : ""} aria-label="注文" onClick={() => setView("orders")}>
            <OrdersIcon width={18} height={18} />
            <span>注文</span>
          </button>
          <button type="button" className={view === "mail" ? "active" : ""} aria-label="受信箱" onClick={() => setView("mail")}>
            <MailIcon width={18} height={18} />
            <span>受信箱</span>
            {world.mail && <i className="store-dot" />}
          </button>
          <button type="button" className={view === "tool" ? "active" : ""} aria-label="画面" onClick={() => setView("tool")}>
            <ScreenIcon width={18} height={18} />
            <span>{ui?.site ?? "画面"}</span>
          </button>
        </nav>
      </aside>
      <div className="store-body">
        <header className="store-top">
          <div>
            <p className="store-kicker">Harbor</p>
            <h1>{pageTitle}</h1>
          </div>
          <div className="store-user">
            <span className={`store-avatar${world.avatarReplaced ? " replaced" : ""}`} data-testid="store-avatar">
              {world.avatarReplaced ? "画像" : world.account.slice(0, 1).toUpperCase()}
            </span>
            <span data-testid="store-account">{world.account}</span>
          </div>
        </header>
        <main className="store-main">
          {view === "home" && (
            <section className="store-page">
              <div className="store-balance-card">
                <span>利用可能残高</span>
                <strong className="mono" data-testid="store-balance">
                  {money(world.balance)}
                </strong>
                <em>{world.account === "admin" ? "管理者" : "会員"}</em>
              </div>
              <div className="store-panel">
                <div className="store-panel-head">
                  <h2>最近の注文</h2>
                  <button type="button" onClick={() => setView("orders")}>
                    すべて
                  </button>
                </div>
                <OrderList orders={world.orders} />
              </div>
            </section>
          )}
          {view === "orders" && (
            <section className="store-page">
              <div className="store-panel">
                <div className="store-panel-head">
                  <h2>注文 {world.orders.length} 件</h2>
                </div>
                <OrderList orders={world.orders} />
              </div>
            </section>
          )}
          {view === "mail" && (
            <section className="store-page">
              {world.mail ? (
                <div className="store-inbox">
                  <div className="store-inbox-list">
                    <button type="button" className="active">
                      <strong>{world.mail.subject}</strong>
                      <span>Harbor</span>
                    </button>
                  </div>
                  <article className="store-mail" data-testid="store-mail">
                    <p className="store-kicker">Harbor</p>
                    <h2>{world.mail.subject}</h2>
                    <p className="mono">{world.mail.body}</p>
                  </article>
                </div>
              ) : (
                <div className="store-panel store-empty">
                  <MailIcon width={28} height={28} />
                  <p>メールはありません。</p>
                </div>
              )}
            </section>
          )}
          {view === "tool" && (
            <section className="store-page store-tool">
              {remote && ui && lab ? (
                <div className="store-panel store-tool-card">
                  {ui.renderApp({
                    inputs,
                    setField,
                    submit: (patch) => post({ type: "submit", patch: { ...inputs, ...patch } }),
                    result: remote.result,
                    succeeded: remote.succeeded,
                    runId: remote.runId,
                    onFire: (message) => post({ type: "fire", message }),
                    level: remote.level as Level,
                    browserTab: remote.browserTab,
                    setBrowserTab: (id) => post({ type: "tab", id }),
                  })}
                </div>
              ) : (
                <div className="store-panel store-empty">
                  <ScreenIcon width={28} height={28} />
                  <p>作業台でラボを開くと、ここにその画面が出ます。</p>
                </div>
              )}
            </section>
          )}
        </main>
      </div>
    </div>
  );
}

function OrderList({ orders }: { orders: { id: string; item: string; price: string; card: string }[] }) {
  return (
    <div className="store-table" data-testid="store-orders">
      <div className="store-table-head">
        <span />
        <span>注文</span>
        <span>内容</span>
        <span>金額</span>
        <span>カード</span>
      </div>
      <ul>
        {orders.map((order) => (
          <li key={order.id}>
            <span className="store-swatch" aria-hidden="true" />
            <span className="mono">{order.id}</span>
            <span>{order.item}</span>
            <span>{order.price}</span>
            <span className="mono">{order.card}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
