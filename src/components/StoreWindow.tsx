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

  return (
    <div className="store" data-testid="store-window">
      <aside className="store-nav">
        <div className="store-brand">
          <HarborMark width={26} height={26} />
          <span>Harbor</span>
        </div>
        <nav className="store-nav-list">
          <button type="button" className={view === "home" ? "active" : ""} aria-label="ホーム" onClick={() => setView("home")}>
            <HomeIcon />
            <span>ホーム</span>
          </button>
          <button type="button" className={view === "orders" ? "active" : ""} aria-label="注文" onClick={() => setView("orders")}>
            <OrdersIcon />
            <span>注文</span>
          </button>
          <button type="button" className={view === "mail" ? "active" : ""} aria-label="受信箱" onClick={() => setView("mail")}>
            <MailIcon />
            <span>受信箱</span>
            {world.mail && <i className="store-dot" />}
          </button>
          <button type="button" className={view === "tool" ? "active" : ""} aria-label="画面" onClick={() => setView("tool")}>
            <ScreenIcon />
            <span>画面</span>
          </button>
        </nav>
      </aside>
      <main className="store-main">
        {view === "home" && (
          <section className="store-page">
            <h1>ホーム</h1>
            <div className="store-account">
              <span className={`store-avatar${world.avatarReplaced ? " replaced" : ""}`} data-testid="store-avatar">
                {world.avatarReplaced ? "画像" : world.account.slice(0, 1).toUpperCase()}
              </span>
              <div>
                <div data-testid="store-account">{world.account}</div>
                <div className="mono" data-testid="store-balance">
                  {money(world.balance)}
                </div>
              </div>
            </div>
          </section>
        )}
        {view === "orders" && (
          <section className="store-page">
            <h1>注文</h1>
            <ul className="store-orders" data-testid="store-orders">
              {world.orders.map((order) => (
                <li key={order.id}>
                  <span className="mono">{order.id}</span>
                  <span>{order.item}</span>
                  <span>{order.price}</span>
                  <span className="mono">{order.card}</span>
                </li>
              ))}
            </ul>
          </section>
        )}
        {view === "mail" && (
          <section className="store-page">
            <h1>受信箱</h1>
            {world.mail ? (
              <article className="store-mail" data-testid="store-mail">
                <h2>{world.mail.subject}</h2>
                <p className="mono">{world.mail.body}</p>
              </article>
            ) : (
              <p className="store-empty">メールはありません。</p>
            )}
          </section>
        )}
        {view === "tool" && (
          <section className="store-page store-tool">
            <h1>{ui?.site ?? "画面"}</h1>
            {remote && ui && lab ? (
              ui.renderApp({
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
              })
            ) : (
              <p className="store-empty">作業台でラボを開くと、ここにその画面が出ます。</p>
            )}
          </section>
        )}
      </main>
    </div>
  );
}
