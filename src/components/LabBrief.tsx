import type { Level } from "../labs/types";
import { SCENARIOS } from "../target/scenarios";

interface Props {
  labId: string;
  level: Level;
}

/** The situation for this lab and level. Harbor itself is rendered beside it. */
export function LabBrief({ labId, level }: Props) {
  const scenario = SCENARIOS[labId];
  if (!scenario) return null;

  return (
    <div className="brief embedded">
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
            <li><span>1</span>下のアプリで普段の操作をする</li>
            <li><span>2</span>Proxy で止めて改ざんする</li>
            <li><span>3</span>結果はアプリと Harbor に残る</li>
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
