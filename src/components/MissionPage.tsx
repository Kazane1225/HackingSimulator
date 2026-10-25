import { HARBOR_MISSION } from "../missions";
import type { LearningProgress } from "../learningProgress";
import type { Progress } from "../progress";
import { useLoot } from "../loot";
import { Check, Lock, Play, Shield } from "./icons";

interface Props {
  progress: Progress;
  learningProgress: LearningProgress;
  completeStep: (stepId: string) => void;
}

export function MissionPage({ progress, learningProgress, completeStep }: Props) {
  const { items } = useLoot();
  const completed = new Set(learningProgress.completedMissionStepIds);
  const allComplete = HARBOR_MISSION.every((step) => completed.has(step.id));

  return (
    <div className="page mission-page">
      <div className="page-head">
        <div>
          <span className="learning-path-kicker mono">CHAINED CTF</span>
          <h1>Harbor侵害調査</h1>
          <p className="page-lead">
            単発の脆弱性ではなく、前の侵害で得た権限と情報を次の攻撃へつなげます。
            各工程の証拠を記録すると次の工程が解放されます。
          </p>
        </div>
        <span className={`mission-summary ${allComplete ? "complete" : ""}`}>
          <Shield width={18} height={18} />
          {completed.size}/{HARBOR_MISSION.length} 工程
        </span>
      </div>

      {allComplete && (
        <div className="notice ok mission-complete" data-testid="mission-complete">
          <strong>侵害経路の再構成が完了しました。</strong>
          <p>初期侵入、認証突破、トークン偽造、クラウド資格情報の窃取、痕跡偽装が1本の経路としてつながりました。</p>
        </div>
      )}

      <div className="mission-timeline">
        {HARBOR_MISSION.map((step, index) => {
          const done = completed.has(step.id);
          const unlocked = index === 0 || completed.has(HARBOR_MISSION[index - 1].id);
          const levelDone = (progress[step.requirement.labId] ?? []).includes(step.requirement.level);
          const lootDone = !step.requirement.lootId || items.some((item) => item.id === step.requirement.lootId);
          const evidenceReady = levelDone && lootDone;
          return (
            <section
              key={step.id}
              className={`pane mission-step ${done ? "done" : unlocked ? "active" : "locked"}`}
              data-testid={`mission-step-${step.id}`}
            >
              <div className="mission-step-marker">
                {done ? <Check width={16} height={16} /> : unlocked ? step.number : <Lock width={14} height={14} />}
              </div>
              <div className="mission-step-content">
                <div className="pane-head">
                  <span className="pane-title">{step.title}</span>
                  <span className={`status-badge ${done ? "ok" : evidenceReady ? "progress" : ""}`}>
                    {done ? "証拠記録済み" : unlocked ? (evidenceReady ? "証拠あり" : "調査中") : "LOCKED"}
                  </span>
                </div>
                <div className="mission-step-body">
                  <p>{unlocked ? step.briefing : "前の工程で証拠を記録すると、この調査内容が開示されます。"}</p>
                  {unlocked && (
                    <>
                      <div className="mission-objective"><span className="mono">OBJECTIVE</span> {step.objective}</div>
                      <div className="mission-actions">
                        <a className="btn" href={`#/lab/${step.requirement.labId}`}>
                          <Play width={13} height={13} /> 対象ラボを開く
                        </a>
                        <button
                          type="button"
                          className="btn btn-accent"
                          disabled={!evidenceReady || done}
                          onClick={() => completeStep(step.id)}
                        >
                          <Check width={13} height={13} /> 証拠を記録
                        </button>
                      </div>
                      {!evidenceReady && (
                        <p className="dim mission-requirement">
                          必要条件: {step.requirement.labId} Lv{step.requirement.level} クリア
                          {step.requirement.lootId ? ` + ${step.requirement.lootId} を取得` : ""}
                        </p>
                      )}
                      {done && (
                        <div className="mission-artifact">
                          <span className="mono">ARTIFACT</span>
                          <strong>{step.artifact.label}</strong>
                          <p>{step.artifact.description}</p>
                        </div>
                      )}
                    </>
                  )}
                </div>
              </div>
            </section>
          );
        })}
      </div>
    </div>
  );
}

