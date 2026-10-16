import { Fragment, useCallback, useState } from "react";
import type { AttackResult, Lab, LabInput, Level } from "../labs/types";
import { LEVELS } from "../labs/types";
import { BrowserChrome } from "./BrowserChrome";
import { Check, LabIcon, Lock, LockOpen, Play, Reset, Shield } from "./icons";
import { LAB_UI } from "./labUI";
import { RichText } from "./RichText";

type InspectorTab = "hint" | "source" | "solution" | "explain";

interface Props {
  lab: Lab;
  isSolved: (labId: string, level: Level) => boolean;
  markSolved: (labId: string, level: Level) => void;
}

function defaultInputs(lab: Lab): LabInput {
  return Object.fromEntries(lab.fields.map((f) => [f.name, f.default ?? ""]));
}

export function LabPage({ lab, isSolved, markSolved }: Props) {
  const id = lab.meta.id;
  const ui = LAB_UI[id];
  const firstUnsolved = LEVELS.find((lv) => lv < 5 && !isSolved(id, lv)) ?? 5;

  const [level, setLevel] = useState<Level>(firstUnsolved);
  const [inputs, setInputs] = useState<LabInput>(() => defaultInputs(lab));
  const [result, setResult] = useState<AttackResult | null>(null);
  const [runId, setRunId] = useState(0);
  const [fired, setFired] = useState<string | null>(null);
  const [intercept, setIntercept] = useState(true);
  const [held, setHeld] = useState(false);
  const [inspector, setInspector] = useState<InspectorTab>("hint");
  const [hintsShown, setHintsShown] = useState<Partial<Record<Level, number>>>({});

  const spec = lab.levels[level];
  const shownHints = Math.min(hintsShown[level] ?? 1, spec.hints.length);
  const solvedHere = isSolved(id, level);
  // Lv5 cannot be cleared; its write-up unlocks once Lv4 has been beaten.
  const solutionUnlocked = solvedHere || (level === 5 && isSolved(id, 4));
  const executionJudged = result?.renderHtml !== undefined;
  const succeeded = !!result && (executionJudged ? fired !== null : result.solved);

  const setField = (name: string, value: string) => setInputs((prev) => ({ ...prev, [name]: value }));

  const clear = () => {
    setResult(null);
    setFired(null);
    setHeld(false);
  };

  const selectLevel = (lv: Level) => {
    setLevel(lv);
    clear();
  };

  const forward = (requestInputs: LabInput = inputs) => {
    const r = lab.run(level, requestInputs);
    setResult(r);
    setFired(null);
    setHeld(false);
    setRunId((n) => n + 1);
    // Labs that render markup are judged by real execution in the sandboxed
    // iframe (see onFire), not by the heuristic in run().
    if (r.solved && r.renderHtml === undefined) markSolved(id, level);
  };

  /** The target app was used normally: hold the request if intercepting. */
  const submitFromApp = (patch?: LabInput) => {
    const requestInputs = patch ? { ...inputs, ...patch } : inputs;
    if (patch) setInputs(requestInputs);
    if (intercept) {
      setHeld(true);
    } else {
      forward(requestInputs);
    }
  };

  const onFire = useCallback(
    (msg: string) => {
      setFired(msg);
      markSolved(id, level);
    },
    [id, level, markSolved],
  );

  const status = held
    ? { cls: "held", label: "傍受中" }
    : !result
      ? { cls: "idle", label: "待機" }
      : succeeded
        ? { cls: "ok", label: "成功" }
        : level === 5
          ? { cls: "blocked", label: "防御済み" }
          : { cls: "ng", label: "失敗" };

  const inspectorTabs: { key: InspectorTab; label: string; locked?: boolean }[] = [
    { key: "hint", label: "ヒント" },
    { key: "source", label: "ソース" },
    { key: "solution", label: "解答", locked: !solutionUnlocked },
    { key: "explain", label: "解説" },
  ];

  return (
    <div className="page lab wide">
      <div className="lab-toolbar">
        <div className="lab-title">
          <LabIcon id={id} width={20} height={20} className="lab-title-icon" />
          <div>
            <h1>{lab.meta.title}</h1>
            <div className="lab-sub">
              {lab.meta.category} ・ 目標: {lab.meta.objective}
            </div>
          </div>
        </div>
        <div className="segmented" role="tablist" aria-label="セキュリティレベル">
          {LEVELS.map((lv) => (
            <button
              key={lv}
              role="tab"
              aria-selected={lv === level}
              className={`seg ${lv === level ? "active" : ""}`}
              onClick={() => selectLevel(lv)}
              title={lv === 5 ? "正しい実装（突破不可）" : `Lv${lv}`}
            >
              {lv === 5 ? <Shield width={13} height={13} /> : isSolved(id, lv) ? <Check width={13} height={13} /> : null}
              Lv{lv}
            </button>
          ))}
        </div>
      </div>

      <div className="defense-bar">
        <span className="defense-tag mono">防御 Lv{level}</span>
        <span>{spec.defense}</span>
      </div>

      <div className="workbench">
        <section className="wb-target">
          <BrowserChrome url={ui.url} title={ui.site} onReload={clear}>
            {ui.renderApp({ inputs, setField, submit: submitFromApp, result, succeeded, runId, onFire })}
          </BrowserChrome>
        </section>

        <section className="pane wb-proxy">
          <div className="pane-head">
            <span className="pane-title">Proxy</span>
            <label className="toggle" title="ON のとき、標的アプリからの送信をここで止めて改ざんできます">
              <input type="checkbox" checked={intercept} onChange={(e) => setIntercept(e.target.checked)} />
              <span className="toggle-track" />
              Intercept {intercept ? "ON" : "OFF"}
            </label>
          </div>

          <div className={`proxy-req ${held ? "is-held" : ""}`}>
            {held && <div className="held-bar">リクエストを傍受しました。値を改ざんして Forward してください。</div>}
            <pre className="raw mono">{ui.request(inputs).join("\n")}</pre>
            <div className="params">
              <div className="params-head">
                <span>パラメータ</span>
                <span className="dim">ここで直接改ざんできます</span>
              </div>
              {lab.fields.map((f) => (
                <label key={f.name} className="param-row">
                  <span className="param-key mono">{f.name}</span>
                  {f.multiline ? (
                    <textarea
                      className="mono"
                      rows={f.name === "html" ? 6 : 3}
                      value={inputs[f.name] ?? ""}
                      spellCheck={false}
                      onChange={(e) => setField(f.name, e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
                          e.preventDefault();
                          forward();
                        }
                      }}
                    />
                  ) : (
                    <input
                      className="mono"
                      value={inputs[f.name] ?? ""}
                      spellCheck={false}
                      autoComplete="off"
                      onChange={(e) => setField(f.name, e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") {
                          e.preventDefault();
                          forward();
                        }
                      }}
                    />
                  )}
                </label>
              ))}
            </div>
            <div className="proxy-actions">
              <button type="button" className="btn btn-accent" onClick={() => forward()}>
                <Play width={13} height={13} /> Forward
              </button>
              <button
                type="button"
                className="btn"
                onClick={() => {
                  setInputs(defaultInputs(lab));
                  clear();
                }}
              >
                <Reset width={13} height={13} /> 初期化
              </button>
            </div>
          </div>

          <div className="proxy-res">
            <div className="res-head">
              <span className="pane-title">Response</span>
              <span className={`status-badge ${status.cls}`}>{status.label}</span>
            </div>
            {!result ? (
              <div className="empty">Forward するとサーバーの応答がここに表示されます。</div>
            ) : (
              <>
                {(result.note || fired !== null) && (
                  <div className={`notice ${status.cls}`}>
                    {fired !== null && <div>alert() が実行されました: {JSON.stringify(fired)}</div>}
                    {result.note && <div>{result.note}</div>}
                    {succeeded && <div className="notice-strong">Lv{level} クリア — 「解答」タブが解放されました</div>}
                  </div>
                )}
                <pre className="console">{result.output.join("\n")}</pre>
              </>
            )}
          </div>
        </section>

        <section className="pane wb-inspector">
          <div className="pane-head">
            <div className="pane-tabs" role="tablist">
              {inspectorTabs.map((t) => (
                <button
                  key={t.key}
                  role="tab"
                  aria-selected={inspector === t.key}
                  className={`pane-tab ${inspector === t.key ? "active" : ""}`}
                  onClick={() => setInspector(t.key)}
                >
                  {t.key === "solution" &&
                    (t.locked ? <Lock width={12} height={12} /> : <LockOpen width={12} height={12} />)}
                  {t.label}
                </button>
              ))}
            </div>
          </div>
          <div className="inspector-body">
            {inspector === "hint" && (
              <>
                {spec.hints.slice(0, shownHints).map((h, i) => (
                  <div key={i} className="hint-item">
                    <div className="hint-label mono">
                      ヒント {i + 1}/{spec.hints.length}
                    </div>
                    <RichText text={h} />
                  </div>
                ))}
                {shownHints < spec.hints.length ? (
                  <button
                    type="button"
                    className="btn"
                    onClick={() => setHintsShown((prev) => ({ ...prev, [level]: shownHints + 1 }))}
                  >
                    次のヒントを見る
                  </button>
                ) : (
                  <p className="dim hint-end">ヒントはここまでです。クリア後に「解答」タブが開きます。</p>
                )}
              </>
            )}
            {inspector === "source" && (
              <>
                <div className="file-label mono">server.js — Lv{level}（疑似コード）</div>
                <pre className="code">{spec.code}</pre>
              </>
            )}
            {inspector === "solution" &&
              (solutionUnlocked ? (
                <RichText text={spec.solution} />
              ) : (
                <div className="locked">
                  <Lock width={22} height={22} />
                  <p>このレベルをクリアすると表示されます。</p>
                  <p className="dim">
                    {level === 5
                      ? "Lv5 の解説は Lv4 をクリアすると読めるようになります。"
                      : "ヒントとソースを手がかりに挑戦してみましょう。"}
                  </p>
                </div>
              ))}
            {inspector === "explain" && (
              <>
                <RichText text={lab.explanation} />
                <div className="meta-block">
                  <div className="meta-title">分類</div>
                  <dl className="kv">
                    <dt>OWASP</dt>
                    <dd>
                      <a href={lab.meta.standards.owasp.url} target="_blank" rel="noopener noreferrer">
                        {lab.meta.standards.owasp.code} {lab.meta.standards.owasp.name}
                      </a>
                    </dd>
                    {lab.meta.standards.cwe.map((c) => (
                      <Fragment key={c.id}>
                        <dt>CWE</dt>
                        <dd>
                          <a
                            href={`https://cwe.mitre.org/data/definitions/${c.id}.html`}
                            target="_blank"
                            rel="noopener noreferrer"
                          >
                            CWE-{c.id} {c.name}
                          </a>
                        </dd>
                      </Fragment>
                    ))}
                  </dl>
                  <div className="meta-title">参考資料</div>
                  <ul className="ref-list">
                    {lab.meta.references.map((r) => (
                      <li key={r.url}>
                        <a href={r.url} target="_blank" rel="noopener noreferrer">
                          {r.title}
                        </a>
                      </li>
                    ))}
                    <li>
                      <a href="#/glossary">用語集</a>
                    </li>
                  </ul>
                </div>
              </>
            )}
          </div>
        </section>
      </div>
    </div>
  );
}
