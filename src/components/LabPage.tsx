import { Fragment, useCallback, useRef, useState } from "react";
import type { AttackResult, Lab, LabField, LabInput, Level } from "../labs/types";
import { LEVELS } from "../labs/types";
import { useLoot } from "../loot";
import {
  buildLabRequest,
  executeLabRequest,
  formatRawRequest,
  formatRawResponse,
  judgeLabResponse,
  type HttpResponse,
} from "../realHttp";
import { useRealLabs } from "../realServer";
import { BrowserChrome } from "./BrowserChrome";
import { Check, LabIcon, Lock, LockOpen, Play, Reset, Shield } from "./icons";
import { LAB_UI } from "./labUI";
import { RichText } from "./RichText";

type InspectorTab = "hint" | "source" | "solution" | "explain";

/** On narrow screens the three workbench panes are shown one at a time. */
type MobileTab = "target" | "proxy" | "inspector";
const MOBILE_TABS: { key: MobileTab; label: string }[] = [
  { key: "target", label: "標的アプリ" },
  { key: "proxy", label: "Proxy" },
  { key: "inspector", label: "ヒント・解説" },
];

interface Props {
  lab: Lab;
  isSolved: (labId: string, level: Level) => boolean;
  markSolved: (labId: string, level: Level) => void;
}

function defaultInputs(lab: Lab): LabInput {
  return Object.fromEntries(lab.fields.filter((f) => !f.hidden).map((f) => [f.name, f.default ?? ""]));
}

function assembledDuplicatesOutput(assembled: string | undefined, output: string[]): boolean {
  const a = assembled?.trim() ?? "";
  if (!a) return true;
  return output.join("\n").includes(a);
}

export function LabPage({ lab, isSolved, markSolved }: Props) {
  const id = lab.meta.id;
  const ui = LAB_UI[id];
  const firstUnsolved = LEVELS.find((lv) => lv < 5 && !isSolved(id, lv)) ?? 5;

  const [level, setLevel] = useState<Level>(firstUnsolved);
  const [inputs, setInputs] = useState<LabInput>(() => defaultInputs(lab));
  const [result, setResult] = useState<AttackResult | null>(null);
  const [httpResponse, setHttpResponse] = useState<HttpResponse | null>(null);
  const [runId, setRunId] = useState(0);
  const [fired, setFired] = useState<string | null>(null);
  const [intercept, setIntercept] = useState(true);
  const [held, setHeld] = useState(false);
  const [inspector, setInspector] = useState<InspectorTab>("hint");
  const [hintsShown, setHintsShown] = useState<Partial<Record<Level, number>>>({});
  const [mobileTab, setMobileTab] = useState<MobileTab>("target");
  const [revealed, setRevealed] = useState<string[]>([]);
  const [extraParams, setExtraParams] = useState<string[]>([]);
  const [newParamName, setNewParamName] = useState("");
  const [focusField, setFocusField] = useState<string | null>(null);
  const { items: loot, ingest } = useLoot();

  const browserTabs = ui.browserTabs ?? [{ id: "app", url: ui.url, title: ui.site }];
  const [browserTab, setBrowserTab] = useState(browserTabs[0].id);

  const realAvailable = useRealLabs().includes(id);
  const [realMode, setRealMode] = useState(false);
  const viaReal = realMode && realAvailable;
  // Bumped whenever the pending result is no longer wanted (new request, level change, reset).
  const requestSeq = useRef(0);

  const spec = lab.levels[level];
  const shownHints = Math.min(hintsShown[level] ?? 1, spec.hints.length);
  const solvedHere = isSolved(id, level);
  // Lv5 cannot be cleared; its write-up unlocks once Lv4 has been beaten.
  const solutionUnlocked = solvedHere || (level === 5 && isSolved(id, 4));
  const executionJudged = result?.renderHtml !== undefined;
  const succeeded = !!result && (executionJudged ? fired !== null : result.solved);
  const progress = !!result && !succeeded && !!result.progress;
  const benign = !!result && !succeeded && !!result.benign && !progress;

  const setField = (name: string, value: string) => setInputs((prev) => ({ ...prev, [name]: value }));

  const clear = () => {
    requestSeq.current++;
    setResult(null);
    setHttpResponse(null);
    setFired(null);
    setHeld(false);
    setBrowserTab(browserTabs[0].id);
  };

  const selectLevel = (lv: Level) => {
    setLevel(lv);
    setRevealed([]);
    setExtraParams([]);
    setNewParamName("");
    clear();
  };

  const knownVisible = lab.fields.filter(
    (f) => !f.hidden || revealed.includes(f.name) || ((inputs[f.name] ?? "") !== (f.default ?? "") && (inputs[f.name] ?? "") !== ""),
  );
  const visibleFields: LabField[] = [
    ...knownVisible,
    ...extraParams
      .filter((name) => !knownVisible.some((f) => f.name === name))
      .map((name) => ({ name, label: name, mono: true })),
  ];
  const canAddParams = lab.fields.some((f) => f.hidden);

  const addNamedParam = (raw: string) => {
    const name = raw.trim();
    if (!name) return;
    const known = lab.fields.find((f) => f.name === name);
    if (known?.hidden) {
      setRevealed((prev) => (prev.includes(name) ? prev : [...prev, name]));
      setField(name, inputs[name] ?? known.default ?? "");
    } else if (!known) {
      setExtraParams((prev) => (prev.includes(name) ? prev : [...prev, name]));
      setField(name, inputs[name] ?? "");
    }
    setNewParamName("");
    setFocusField(name);
  };

  const applyResult = (r: AttackResult, requestInputs: LabInput) => {
    setResult(r);
    setFired(null);
    setHeld(false);
    setRunId((n) => n + 1);
    ingest(id, r.loot);
    for (const key of Object.keys(requestInputs)) {
      const field = lab.fields.find((f) => f.name === key && f.hidden);
      if (field && requestInputs[key] !== (field.default ?? "")) {
        setRevealed((prev) => (prev.includes(key) ? prev : [...prev, key]));
      }
    }
    // Labs that render markup are judged by real execution in the sandboxed
    // iframe (see onFire), not by the heuristic in run().
    if (level < 5 && r.solved && r.renderHtml === undefined) markSolved(id, level);
  };

  const forward = (requestInputs: LabInput = inputs) => {
    const seq = ++requestSeq.current;
    if (!viaReal) {
      setHttpResponse(null);
      applyResult(lab.run(level, requestInputs), requestInputs);
      return;
    }
    const request = buildLabRequest(id, level, requestInputs);
    executeLabRequest("api", request)
      .then((http) => {
        if (seq !== requestSeq.current) return;
        setHttpResponse(http);
        applyResult(judgeLabResponse(id, level, requestInputs, http), requestInputs);
      })
      .catch((err: unknown) => {
        if (seq !== requestSeq.current) return;
        setHttpResponse(null);
        applyResult(
          {
            solved: false,
            output: [`実サーバーに接続できませんでした: ${err instanceof Error ? err.message : String(err)}`],
            note: "実サーバーが起動しているか確認してください（docker compose -f docker-compose.real.yml up）。",
          },
          requestInputs,
        );
      });
  };

  /** The target app was used normally: hold the request if intercepting. */
  const submitFromApp = (patch?: LabInput) => {
    const requestInputs = patch ? { ...inputs, ...patch } : inputs;
    if (patch) {
      setInputs(requestInputs);
      for (const key of Object.keys(patch)) {
        if (lab.fields.some((f) => f.name === key && f.hidden)) {
          setRevealed((prev) => (prev.includes(key) ? prev : [...prev, key]));
        }
      }
    }
    if (intercept) {
      setHeld(true);
      setMobileTab("proxy");
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

  const labLoot = loot.filter((item) => item.labId === id);

  const status = held
    ? { cls: "held", label: "傍受中" }
    : !result
      ? { cls: "idle", label: "待機" }
      : succeeded
        ? { cls: "ok", label: "成功" }
        : level === 5
          ? { cls: "blocked", label: "防御済み" }
          : progress
            ? { cls: "progress", label: "進展あり" }
            : benign
              ? { cls: "benign", label: "通常応答" }
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
        {realAvailable && (
          <div className="segmented mode-switch" role="group" aria-label="標的の種類" data-testid="mode-switch">
            <button
              className={`seg ${!realMode ? "active" : ""}`}
              aria-pressed={!realMode}
              onClick={() => {
                setRealMode(false);
                clear();
              }}
              title="ブラウザ内の疑似サーバー"
            >
              シミュレート
            </button>
            <button
              className={`seg ${realMode ? "active" : ""}`}
              aria-pressed={realMode}
              onClick={() => {
                setRealMode(true);
                clear();
              }}
              title="実際に動く脆弱なサーバー（隔離コンテナ）"
            >
              実サーバー
            </button>
          </div>
        )}
      </div>

      <div className="mobile-tabs" role="tablist" aria-label="表示ペイン" data-testid="mobile-tabs">
        {MOBILE_TABS.map((t) => (
          <button
            key={t.key}
            role="tab"
            aria-selected={mobileTab === t.key}
            className={`mobile-tab ${mobileTab === t.key ? "active" : ""}`}
            onClick={() => setMobileTab(t.key)}
          >
            {t.label}
            {t.key === "proxy" && held && <span className="mobile-tab-dot" aria-label="傍受中" />}
          </button>
        ))}
      </div>

      <div className={`workbench show-${mobileTab}`}>
        <section className="wb-target" data-testid="pane-target">
          <BrowserChrome
            tabs={browserTabs}
            activeTabId={browserTab}
            onTabChange={setBrowserTab}
            onReload={clear}
          >
            {ui.renderApp({
              inputs,
              setField,
              submit: submitFromApp,
              result,
              succeeded,
              runId,
              onFire,
              level,
              browserTab,
              setBrowserTab,
            })}
          </BrowserChrome>
        </section>

        <section className="pane wb-proxy" data-testid="pane-proxy">
          <div className="pane-head">
            <span className="pane-title">Proxy</span>
            <label className="toggle" title="ON のとき、標的アプリからの送信をここで止めて改ざんできます">
              <input type="checkbox" checked={intercept} onChange={(e) => setIntercept(e.target.checked)} />
              <span className="toggle-track" />
              Intercept {intercept ? "ON" : "OFF"}
            </label>
          </div>

          <div className={`proxy-req ${held ? "is-held" : ""}`}>
            {held && (
              <div className="held-bar" data-testid="held-bar">
                リクエストを傍受しました。値を改ざんして Forward してください。
              </div>
            )}
            <pre className="raw mono">{viaReal ? formatRawRequest(buildLabRequest(id, level, inputs)) : ui.request(inputs).join("\n")}</pre>
            <div className="params">
              <div className="params-head">
                <span>パラメータ</span>
                <span className="dim">ここで直接改ざんできます</span>
              </div>
              {visibleFields.map((f) => (
                <label key={f.name} className="param-row">
                  <span className="param-key mono">{f.name}</span>
                  {f.multiline ? (
                    <textarea
                      className="mono"
                      aria-label={f.name}
                      rows={f.name === "html" || f.name === "query" ? 6 : 3}
                      value={inputs[f.name] ?? ""}
                      spellCheck={false}
                      autoCapitalize="off"
                      autoCorrect="off"
                      onFocus={() => setFocusField(f.name)}
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
                      aria-label={f.name}
                      value={inputs[f.name] ?? ""}
                      spellCheck={false}
                      autoComplete="off"
                      autoCapitalize="off"
                      autoCorrect="off"
                      onFocus={() => setFocusField(f.name)}
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
              {canAddParams && (
                <div className="param-add">
                  <div className="param-add-row">
                    <input
                      type="text"
                      aria-label="新しいパラメータ名"
                      placeholder="パラメータ名"
                      spellCheck={false}
                      autoCapitalize="off"
                      autoCorrect="off"
                      value={newParamName}
                      onChange={(e) => setNewParamName(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") {
                          e.preventDefault();
                          addNamedParam(newParamName);
                        }
                      }}
                    />
                    <button type="button" className="btn" onClick={() => addNamedParam(newParamName)}>
                      追加
                    </button>
                  </div>
                </div>
              )}
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
                  setRevealed([]);
                  setExtraParams([]);
                  setNewParamName("");
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
              <span className={`status-badge ${status.cls}`} data-testid="status-badge">
                {status.label}
              </span>
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
                    {succeeded && result.recap && result.recap.length > 0 && (
                      <ol className="recap">
                        {result.recap.map((step) => (
                          <li key={step}>{step}</li>
                        ))}
                      </ol>
                    )}
                  </div>
                )}
                {httpResponse ? (
                  <pre className="console" data-testid="http-response">{formatRawResponse(httpResponse)}</pre>
                ) : (
                  <>
                    {result.assembled && !assembledDuplicatesOutput(result.assembled, result.output) && (
                      <div className="assembled">
                        <div className="assembled-label mono">サーバーが組み立てた処理</div>
                        <pre className="console assembled-pre">{result.assembled}</pre>
                      </div>
                    )}
                    <details key={runId} className="console-details">
                      <summary>コンソール（詳細）</summary>
                      <pre className="console">{result.output.join("\n")}</pre>
                    </details>
                  </>
                )}
                {labLoot.length > 0 && (
                  <div className="loot">
                    <div className="loot-label mono">戦利品</div>
                    <p className="dim loot-hint">このラボで見つけた秘密です。クリックでフォーカス中のパラメータへ挿入します。</p>
                    <div className="loot-list">
                      {labLoot.map((item) => (
                        <button
                          key={`${item.labId}-${item.id}`}
                          type="button"
                          className="loot-chip"
                          title={item.value}
                          onClick={() => {
                            const target = focusField ?? visibleFields[0]?.name;
                            if (target) setField(target, item.value);
                            void navigator.clipboard?.writeText(item.value).catch(() => undefined);
                          }}
                        >
                          <span className="loot-chip-lab">{item.label}</span>
                          <span className="loot-chip-val mono">{item.value}</span>
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        </section>

        <section className="pane wb-inspector" data-testid="pane-inspector">
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
                  <div key={i} className="hint-item" data-testid="hint-item">
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
                <div className="locked" data-testid="solution-locked">
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
