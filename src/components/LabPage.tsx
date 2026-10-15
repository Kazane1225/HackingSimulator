import { useCallback, useMemo, useState } from "react";
import type { AttackResult, Lab, LabInput, Level } from "../labs/types";
import { LEVELS } from "../labs/types";
import { RichText } from "./RichText";
import { XssPreview } from "./XssPreview";

type Tab = "hint" | "code" | "solution" | "explain";

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
  const [tab, setTab] = useState<Tab>("hint");

  const spec = lab.levels[level];
  const solvedHere = isSolved(id, level);
  // Lv5 cannot be cleared; its write-up unlocks once Lv4 has been beaten.
  const solutionUnlocked = solvedHere || (level === 5 && isSolved(id, 4));
  const succeeded = !!result && (result.solved || fired !== null);

  const selectLevel = (lv: Level) => {
    setLevel(lv);
    setResult(null);
    setFired(null);
  };

  const attack = () => {
    const r = lab.run(level, inputs);
    setResult(r);
    setFired(null);
    setRunId((n) => n + 1);
    if (r.solved) markSolved(id, level);
  };

  const onFire = useCallback(
    (msg: string) => {
      setFired(msg);
      markSolved(id, level);
    },
    [id, level, markSolved],
  );

  const tabs = useMemo(
    () =>
      [
        { key: "hint", label: "ヒント" },
        { key: "code", label: "サーバー側コード" },
        { key: "solution", label: solutionUnlocked ? "解答" : "🔒 解答" },
        { key: "explain", label: "解説" },
      ] as { key: Tab; label: string }[],
    [solutionUnlocked],
  );

  return (
    <div className="lab">
      <a href="#/" className="back">
        ← ラボ一覧
      </a>
      <header className="lab-header">
        <span className="lab-icon big">{lab.meta.icon}</span>
        <div>
          <div className="lab-category">{lab.meta.category}</div>
          <h1>{lab.meta.title}</h1>
          <p className="objective">
            <strong>🎯 目標:</strong> {lab.meta.objective}
          </p>
        </div>
      </header>

      <div className="level-tabs" role="tablist" aria-label="セキュリティレベル">
        {LEVELS.map((lv) => (
          <button
            key={lv}
            role="tab"
            aria-selected={lv === level}
            className={`level-tab ${lv === level ? "active" : ""} ${isSolved(id, lv) ? "done" : ""}`}
            onClick={() => selectLevel(lv)}
          >
            Lv{lv}
            {lv === 5 && <span className="tag">Impossible</span>}
            {isSolved(id, lv) && <span className="check">✓</span>}
          </button>
        ))}
      </div>

      <div className="defense">
        <span className="defense-label">このレベルの防御</span>
        {spec.defense}
      </div>

      <div className="lab-body">
        <section className="panel attack">
          <h2>攻撃</h2>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              attack();
            }}
          >
            {lab.fields.map((f) => (
              <label key={f.name} className="field">
                <span>{f.label}</span>
                {f.multiline ? (
                  <textarea
                    className={f.mono ? "mono" : ""}
                    rows={4}
                    placeholder={f.placeholder}
                    value={inputs[f.name] ?? ""}
                    spellCheck={false}
                    onChange={(e) => setInputs({ ...inputs, [f.name]: e.target.value })}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
                        e.preventDefault();
                        attack();
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
            <div className="actions">
              <button type="submit" className="btn-primary">
                攻撃を実行 ▶
              </button>
              <button
                type="button"
                className="btn-ghost"
                onClick={() => {
                  setInputs(defaultInputs(lab));
                  setResult(null);
                  setFired(null);
                }}
              >
                入力をリセット
              </button>
              {lab.fields.some((f) => f.multiline) && (
                <span className="kbd-hint">Ctrl + Enter でも実行</span>
              )}
            </div>
          </form>

          {result && (
            <div className={`result ${succeeded ? "ok" : "ng"}`}>
              <div className="result-banner">
                {succeeded
                  ? `🎉 攻撃成功！ Lv${level} クリア`
                  : level === 5
                    ? "🛡 防御に阻まれました（Lv5 は正しい実装です）"
                    : "❌ 攻撃は失敗しました"}
              </div>
              {fired !== null && (
                <div className="fired">alert() が実行されました: {JSON.stringify(fired)}</div>
              )}
              {result.note && <div className="note">{result.note}</div>}
              <pre className="terminal">{result.output.join("\n")}</pre>
              {result.renderHtml !== undefined && (
                <div className="preview">
                  <div className="preview-label">ブラウザでの表示（サンドボックス iframe）</div>
                  <XssPreview html={result.renderHtml} runId={runId} onFire={onFire} />
                </div>
              )}
            </div>
          )}
        </section>

        <section className="panel learn">
          <div className="learn-tabs" role="tablist">
            {tabs.map((t) => (
              <button
                key={t.key}
                role="tab"
                aria-selected={tab === t.key}
                className={`learn-tab ${tab === t.key ? "active" : ""}`}
                onClick={() => setTab(t.key)}
              >
                {t.label}
              </button>
            ))}
          </div>
          <div className="learn-body">
            {tab === "hint" && <RichText text={spec.hint} />}
            {tab === "code" && (
              <>
                <p className="muted">Lv{level} のサーバー側処理（疑似コード）。防御の穴を探してみましょう。</p>
                <pre className="code">{spec.code}</pre>
              </>
            )}
            {tab === "solution" &&
              (solutionUnlocked ? (
                <RichText text={spec.solution} />
              ) : (
                <div className="locked">
                  <p>🔒 解答はこのレベルをクリアすると表示されます。</p>
                  <p className="muted">
                    {level === 5
                      ? "Lv5 の解説は Lv4 をクリアすると読めるようになります。"
                      : "まずはヒントとサーバー側コードを手がかりに挑戦してみましょう。"}
                  </p>
                </div>
              ))}
            {tab === "explain" && <RichText text={lab.explanation} />}
          </div>
        </section>
      </div>
    </div>
  );
}
