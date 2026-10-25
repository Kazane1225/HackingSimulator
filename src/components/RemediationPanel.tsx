import { useMemo, useState } from "react";
import type { Lab, Level } from "../labs/types";
import { Check, Play, Shield } from "./icons";

interface Props {
  lab: Lab;
  completed: boolean;
  onComplete: () => void;
}

const CANDIDATE_LEVELS: Level[] = [3, 5, 2, 4];
const LABELS = ["Patch A", "Patch B", "Patch C", "Patch D"];

export function RemediationPanel({ lab, completed, onComplete }: Props) {
  const [selected, setSelected] = useState<number | null>(null);
  const [tested, setTested] = useState(false);
  const remediation = lab.remediation;
  const results = useMemo(() => {
    if (selected === null) return [];
    const candidate = CANDIDATE_LEVELS[selected];
    return ([1, 2, 3, 4] as const).map((attackLevel) => ({
      attackLevel,
      blocked: !lab.run(candidate, lab.exploits[attackLevel]).solved,
    }));
  }, [lab, selected]);
  const passed = tested && results.length === 4 && results.every((result) => result.blocked);

  if (!remediation) return <div className="pane remediation-empty">このラボの修正演習は準備中です。</div>;

  const runTests = () => {
    if (selected === null) return;
    setTested(true);
    if (results.every((result) => result.blocked)) onComplete();
  };

  return (
    <div className="remediation" data-testid="remediation-panel">
      <section className="pane remediation-brief">
        <div className="pane-head">
          <span className="pane-title"><Shield width={15} height={15} /> 修正ミッション</span>
          {completed && <span className="status-badge ok"><Check width={12} height={12} /> 修了</span>}
        </div>
        <div className="remediation-copy">
          <p className="page-lead">{remediation.objective}</p>
          <p>
            コードレビュー担当として、4つの修正案から本番へ出せるものを選んでください。
            選んだコードには、既知の攻撃ペイロードを自動で再実行します。
          </p>
          <div className="meta-title">レビュー観点</div>
          <ul className="review-checklist">
            {remediation.checklist.map((item) => <li key={item}>{item}</li>)}
          </ul>
        </div>
      </section>

      <div className="patch-grid" role="radiogroup" aria-label="修正候補">
        {CANDIDATE_LEVELS.map((candidate, index) => (
          <button
            key={candidate}
            type="button"
            role="radio"
            aria-checked={selected === index}
            className={`pane patch-card ${selected === index ? "selected" : ""}`}
            onClick={() => {
              setSelected(index);
              setTested(false);
            }}
          >
            <div className="pane-head"><span className="pane-title mono">{LABELS[index]}</span></div>
            <pre className="code">{lab.levels[candidate].code}</pre>
          </button>
        ))}
      </div>

      <section className="pane regression-panel">
        <div className="pane-head">
          <span className="pane-title">Security regression</span>
          <button className="btn btn-accent" type="button" disabled={selected === null} onClick={runTests}>
            <Play width={13} height={13} /> 攻撃テストを実行
          </button>
        </div>
        {!tested ? (
          <div className="empty">修正案を選び、Lv1〜4で見つかった攻撃を再実行してください。</div>
        ) : (
          <div className="regression-results" data-testid="regression-results">
            {results.map((result) => (
              <div key={result.attackLevel} className={`regression-row ${result.blocked ? "ok" : "ng"}`}>
                <span className="mono">Exploit Lv{result.attackLevel}</span>
                <span>{result.blocked ? "BLOCKED" : "STILL EXPLOITABLE"}</span>
              </div>
            ))}
            <div className={`notice ${passed ? "ok" : "ng"}`}>
              <strong>{passed ? "修正完了" : "回帰テスト失敗"}</strong>
              <p>{passed ? remediation.reviewNote : "少なくとも1つの既知攻撃が通ります。別の修正案をレビューしてください。"}</p>
            </div>
          </div>
        )}
      </section>
    </div>
  );
}

