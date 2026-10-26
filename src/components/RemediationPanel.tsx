import { useState } from "react";
import type { AttackResult, Lab, LabInput, Level } from "../labs/types";
import { PATCH_LABELS, patchOrder, reviewCode } from "../remediation";
import { Check, Play, Shield } from "./icons";
import { RichText } from "./RichText";

interface Props {
  lab: Lab;
  completed: boolean;
  onComplete: () => void;
  isSolved: (level: Level) => boolean;
}

type AttackLevel = 1 | 2 | 3 | 4;
type Prediction = "pass" | "block";

const ATTACK_LEVELS: AttackLevel[] = [1, 2, 3, 4];

interface Outcome {
  attackLevel: AttackLevel;
  blocked: boolean;
  result: AttackResult;
}

interface TestRun {
  patch: number;
  predictions: Record<AttackLevel, Prediction>;
  outcomes: Outcome[];
}

function formatPayload(input: LabInput): string {
  return Object.entries(input)
    .filter(([, value]) => value !== "")
    .map(([name, value]) => `${name}: ${value}`)
    .join("\n");
}

function serverTrace(result: AttackResult): string {
  return result.assembled?.trim() || result.output.slice(0, 8).join("\n");
}

export function RemediationPanel({ lab, completed, onComplete, isSolved }: Props) {
  const order = patchOrder(lab.meta.id);
  const [selected, setSelected] = useState<number | null>(null);
  const [predictions, setPredictions] = useState<Partial<Record<AttackLevel, Prediction>>>({});
  const [run, setRun] = useState<TestRun | null>(null);
  const remediation = lab.remediation;

  if (!remediation) return <div className="pane remediation-empty">このラボの修正演習は準備中です。</div>;

  const allAttacksCleared = ATTACK_LEVELS.every((lv) => isSolved(lv));
  const predicted = ATTACK_LEVELS.every((lv) => predictions[lv] !== undefined);

  const selectPatch = (index: number) => {
    setSelected(index);
    setPredictions({});
    setRun(null);
  };

  const runTests = () => {
    if (selected === null || !predicted) return;
    const level = order[selected];
    const outcomes = ATTACK_LEVELS.map((attackLevel) => {
      const result = lab.run(level, lab.exploits[attackLevel]);
      return { attackLevel, blocked: !result.solved, result };
    });
    setRun({ patch: selected, predictions: predictions as Record<AttackLevel, Prediction>, outcomes });
    if (outcomes.every((o) => o.blocked)) onComplete();
  };

  const testedLevel = run ? order[run.patch] : null;
  const passed = !!run && run.outcomes.every((o) => o.blocked);
  const hits = run ? run.outcomes.filter((o) => (o.blocked ? "block" : "pass") === run.predictions[o.attackLevel]).length : 0;
  const breaches = run ? run.outcomes.filter((o) => !o.blocked) : [];

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
            選んだ修正案に既知の攻撃が通るかを予想してから、実際に攻撃を再実行して確かめます。
          </p>
          <div className="meta-title">レビュー観点</div>
          <ul className="review-checklist">
            {remediation.checklist.map((item) => <li key={item}>{item}</li>)}
          </ul>
          {!allAttacksCleared && (
            <p className="dim remediation-spoiler-note">
              攻撃演習で未クリアのレベルは、失敗時に攻撃の中身と破り方を伏せて表示します。先に Lv1〜4 をクリアすると、解説まで読めます。
            </p>
          )}
        </div>
      </section>

      <div className="patch-grid" role="radiogroup" aria-label="修正候補">
        {order.map((level, index) => (
          <button
            key={level}
            type="button"
            role="radio"
            aria-checked={selected === index}
            className={`pane patch-card ${selected === index ? "selected" : ""}`}
            onClick={() => selectPatch(index)}
          >
            <div className="pane-head"><span className="pane-title mono">{PATCH_LABELS[index]}</span></div>
            <pre className="code">{reviewCode(lab.levels[level].code)}</pre>
          </button>
        ))}
      </div>

      <section className="pane regression-panel">
        <div className="pane-head">
          <span className="pane-title">
            Security regression{selected !== null && <span className="mono dim"> — {PATCH_LABELS[selected]}</span>}
          </span>
          <button
            className="btn btn-accent"
            type="button"
            disabled={selected === null || !predicted}
            onClick={runTests}
          >
            <Play width={13} height={13} /> 攻撃テストを実行
          </button>
        </div>

        {selected === null ? (
          <div className="empty">まず修正案を1つ選んでください。</div>
        ) : (
          <div className="regression-results" data-testid="regression-results">
            <p className="dim prediction-lead">
              {run ? "予想と結果を比べてください。" : "実行する前に、この修正案に各レベルの攻撃が通るかを予想してください。"}
            </p>
            {ATTACK_LEVELS.map((attackLevel) => {
              const outcome = run?.outcomes.find((o) => o.attackLevel === attackLevel);
              const guess = run ? run.predictions[attackLevel] : predictions[attackLevel];
              const hit = outcome ? (outcome.blocked ? "block" : "pass") === guess : null;
              return (
                <div
                  key={attackLevel}
                  className={`regression-row ${outcome ? (outcome.blocked ? "ok" : "ng") : ""}`}
                  data-testid={`regression-row-${attackLevel}`}
                >
                  <span className="mono">Lv{attackLevel} の攻撃</span>
                  {outcome ? (
                    <span className="regression-verdict">
                      <span className="dim">予想: {guess === "block" ? "防ぐ" : "通る"}</span>
                      <span>{outcome.blocked ? "BLOCKED" : "STILL EXPLOITABLE"}</span>
                      <span className={`prediction-mark ${hit ? "hit" : "miss"}`}>{hit ? "的中" : "外れ"}</span>
                    </span>
                  ) : (
                    <span className="segmented prediction-toggle" role="radiogroup" aria-label={`Lv${attackLevel} の攻撃の予想`}>
                      {(["pass", "block"] as const).map((value) => (
                        <button
                          key={value}
                          type="button"
                          role="radio"
                          aria-checked={guess === value}
                          className={`seg ${guess === value ? "active" : ""}`}
                          onClick={() => setPredictions((prev) => ({ ...prev, [attackLevel]: value }))}
                        >
                          {value === "pass" ? "通る" : "防ぐ"}
                        </button>
                      ))}
                    </span>
                  )}
                </div>
              );
            })}

            {run && testedLevel !== null && (
              <>
                <div className="prediction-score mono">予想の的中 {hits}/{ATTACK_LEVELS.length}</div>

                {breaches.map((breach) => (
                  <div key={breach.attackLevel} className="breach" data-testid="breach">
                    <div className="breach-title">Lv{breach.attackLevel} の攻撃がこの修正案を突破しました</div>
                    {isSolved(breach.attackLevel) ? (
                      <>
                        <div className="assembled-label mono">送られた入力</div>
                        <pre className="console">{formatPayload(lab.exploits[breach.attackLevel])}</pre>
                        <div className="assembled-label mono">サーバーが組み立てた処理</div>
                        <pre className="console">{serverTrace(breach.result)}</pre>
                      </>
                    ) : (
                      <p className="dim">攻撃演習で Lv{breach.attackLevel} をクリアすると、通った入力とサーバーの処理が表示されます。</p>
                    )}
                  </div>
                ))}

                <div className={`notice ${passed ? "ok" : "ng"}`}>
                  <strong>{passed ? "修正完了" : "回帰テスト失敗"}</strong>
                  <p>この修正案の方針: {lab.levels[testedLevel].defense}</p>
                  {passed ? (
                    <p>{remediation.reviewNote}</p>
                  ) : isSolved(testedLevel) ? (
                    <div className="breach-why">
                      <div className="meta-title">なぜ破られたか</div>
                      <RichText text={lab.levels[testedLevel].solution} />
                    </div>
                  ) : (
                    <p className="dim">攻撃演習で Lv{testedLevel} をクリアすると、この修正案の破り方の解説が読めます。</p>
                  )}
                </div>
              </>
            )}
          </div>
        )}
      </section>

      {completed && (
        <section className="pane answer-key" data-testid="answer-key">
          <div className="pane-head"><span className="pane-title">答え合わせ — 4つの修正案の正体</span></div>
          <div className="answer-key-body">
            {order.map((level, index) => (
              <div key={level} className={`answer-row ${level === 5 ? "ok" : ""}`}>
                <span className="mono">{PATCH_LABELS[index]}</span>
                <span>{lab.levels[level].defense}</span>
                <span className="dim">{level === 5 ? "既知の攻撃をすべて防ぐ" : `Lv${level} の攻撃で突破される`}</span>
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
