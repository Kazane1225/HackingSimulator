import type { Level } from "../labs/types";
import { HarborMark } from "../target/icons";
import { openTargetApp } from "../target/link";
import { SCENARIOS } from "../target/scenarios";

interface Props {
  labId: string;
  level: Level;
}

/** The workbench pane for a lab: the situation, and the button that opens Harbor. */
export function LabBrief({ labId, level }: Props) {
  const scenario = SCENARIOS[labId];
  if (!scenario) return null;

  return (
    <div className="brief">
      <header className="brief-top">
        <div className="brief-brand">
          <span className="brief-logo">
            <HarborMark width={16} height={16} />
          </span>
          <div>
            <p className="brief-kicker">Harbor · {scenario.place}</p>
            <h2>{scenario.title}</h2>
          </div>
        </div>
        <button type="button" className="btn btn-accent" onClick={openTargetApp}>
          アプリを開く
        </button>
      </header>
      <div className="brief-grid">
        <section className="brief-card brief-situation">
          <h3>状況</h3>
          <p>{scenario.situation}</p>
        </section>
        <section className="brief-card brief-level">
          <h3>このレベル</h3>
          <p>{scenario.levels[level]}</p>
        </section>
        <section className="brief-card brief-howto">
          <h3>進め方</h3>
          <ol className="brief-steps">
            <li><span>1</span>アプリで普段の操作をする</li>
            <li><span>2</span>Proxy で止めて改ざんする</li>
            <li><span>3</span>結果は Harbor に残る</li>
          </ol>
        </section>
        <section className="brief-card brief-success">
          <h3>成功すると</h3>
          <p>{scenario.success}</p>
        </section>
      </div>
    </div>
  );
}
