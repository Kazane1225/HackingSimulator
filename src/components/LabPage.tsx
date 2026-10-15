import { useCallback, useState } from "react";
import type { AttackResult, Lab, LabInput, Level } from "../labs/types";
import { LEVELS } from "../labs/types";
import { Check, LabIcon, Lock, LockOpen, Play, Reset, Shield } from "./icons";
import { RichText } from "./RichText";
import { XssPreview } from "./XssPreview";

type InspectorTab = "hint" | "source" | "solution" | "explain";
type ResponseTab = "raw" | "render";

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
  const firstUnsolved = LEVELS.find((lv) => lv < 5 && !isSolved(id, lv)) ?? 5;

  const [level, setLevel] = useState<Level>(firstUnsolved);
  const [inputs, setInputs] = useState<LabInput>(() => defaultInputs(lab));
  const [result, setResult] = useState<AttackResult | null>(null);
  const [runId, setRunId] = useState(0);
  const [fired, setFired] = useState<string | null>(null);
  const [inspector, setInspector] = useState<InspectorTab>("hint");
  const [responseTab, setResponseTab] = useState<ResponseTab>("raw");

  const spec = lab.levels[level];
  const solvedHere = isSolved(id, level);
  // Lv5 cannot be cleared; its write-up unlocks once Lv4 has been beaten.
  const solutionUnlocked = solvedHere || (level === 5 && isSolved(id, 4));
  const succeeded = !!result && (result.solved || fired !== null);
  const hasRender = result?.renderHtml !== undefined;

  const selectLevel = (lv: Level) => {
    setLevel(lv);
    setResult(null);
    setFired(null);
  };

  const send = () => {
    const r = lab.run(level, inputs);
    setResult(r);
    setFired(null);
    setRunId((n) => n + 1);
    if (r.renderHtml !== undefined) setResponseTab("render");
    if (r.solved) markSolved(id, level);
  };

  const onFire = useCallback(
    (msg: string) => {
      setFired(msg);
      markSolved(id, level);
    },
    [id, level, markSolved],
  );

  const status = !result
    ? { cls: "idle", label: "未送信" }
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
    <div className="page lab">
      <div className="lab-toolbar">
        <div className="lab-title">
          <LabIcon id={id} width={20} height={20} className="lab-title-icon" />
          <div>
            <h1>{lab.meta.title}</h1>
            <div className="lab-sub">{lab.meta.category}</div>
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

      <dl className="brief">
        <dt>目標</dt>
        <dd>{lab.meta.objective}</dd>
        <dt>防御 Lv{level}</dt>
        <dd>{spec.defense}</dd>
      </dl>

      <div className="lab-grid">
        <div className="lab-col">
          <section className="pane">
            <div className="pane-head">
              <span className="pane-title">リクエスト</span>
              <span className="pane-meta">{lab.fields.some((f) => f.multiline) ? "Ctrl+Enter で送信" : "Enter で送信"}</span>
            </div>
            <form
              className="request"
              onSubmit={(e) => {
                e.preventDefault();
                send();
              }}
            >
              {lab.fields.map((f) => (
                <label key={f.name} className="param">
                  <span className="param-name mono">{f.name}</span>
                  <span className="param-label">{f.label}</span>
                  {f.multiline ? (
                    <textarea
                      className={f.mono ? "mono" : ""}
                      rows={5}
                      placeholder={f.placeholder}
                      value={inputs[f.name] ?? ""}
                      spellCheck={false}
                      onChange={(e) => setInputs({ ...inputs, [f.name]: e.target.value })}
                      onKeyDown={(e) => {
                        if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
                          e.preventDefault();
                          send();
                        }
                      }}
                    />
                  ) : (
                    <input
                      className={f.mono ? "mono" : ""}
                      placeholder={f.placeholder}
                      value={inputs[f.name] ?? ""}
                      spellCheck={false}
                      autoComplete="off"
                      onChange={(e) => setInputs({ ...inputs, [f.name]: e.target.value })}
                    />
                  )}
                </label>
              ))}
              <div className="request-actions">
                <button type="submit" className="btn btn-accent">
                  <Play width={13} height={13} /> 送信
                </button>
                <button
                  type="button"
                  className="btn"
                  onClick={() => {
                    setInputs(defaultInputs(lab));
                    setResult(null);
                    setFired(null);
                  }}
                >
                  <Reset width={13} height={13} /> 初期化
                </button>
              </div>
            </form>
          </section>

          <section className="pane">
            <div className="pane-head">
              <div className="pane-tabs">
                <button
                  className={`pane-tab ${responseTab === "raw" ? "active" : ""}`}
                  onClick={() => setResponseTab("raw")}
                >
                  レスポンス
                </button>
                {hasRender && (
                  <button
                    className={`pane-tab ${responseTab === "render" ? "active" : ""}`}
                    onClick={() => setResponseTab("render")}
                  >
                    レンダリング
                  </button>
                )}
              </div>
              <span className={`status-badge ${status.cls}`}>{status.label}</span>
            </div>
            {!result ? (
              <div className="empty">リクエストを送信すると、ここにサーバーの応答が表示されます。</div>
            ) : (
              <>
                {(result.note || fired !== null) && (
                  <div className={`notice ${status.cls}`}>
                    {fired !== null && <div>alert() が実行されました: {JSON.stringify(fired)}</div>}
                    {result.note && <div>{result.note}</div>}
                    {succeeded && <div className="notice-strong">Lv{level} クリア — 「解答」タブが解放されました</div>}
                  </div>
                )}
                {responseTab === "raw" || result.renderHtml === undefined ? (
                  <pre className="console">{result.output.join("\n")}</pre>
                ) : (
                  <div className="render">
                    <XssPreview html={result.renderHtml} runId={runId} onFire={onFire} />
                  </div>
                )}
              </>
            )}
          </section>
        </div>

        <section className="pane inspector">
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
            {inspector === "hint" && <RichText text={spec.hint} />}
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
            {inspector === "explain" && <RichText text={lab.explanation} />}
          </div>
        </section>
      </div>
    </div>
  );
}
