import { useState } from "react";
import type { AttackResult, LabInput, Level } from "../labs/types";
import type { Progress } from "../progress";
import { SCENARIOS } from "../target/scenarios";
import { BrowserChrome } from "./BrowserChrome";
import { LabBrief } from "./LabBrief";
import type { LabUI } from "./labUI";
import { TargetApp } from "./TargetApp";

interface Props {
  labId: string;
  level: Level;
  progress: Progress;
  ui: LabUI;
  inputs: LabInput;
  setField: (name: string, value: string) => void;
  submit: (patch?: LabInput) => void;
  result: AttackResult | null;
  succeeded: boolean;
  runId: number;
  onFire: (message: string) => void;
  browserTab: string;
  setBrowserTab: (id: string) => void;
  harborConnected: boolean;
  popoutNote: string | null;
  onPopout: () => void;
  carryNote: string | null;
}

/** The lab's own screen, with the written scenario tucked above it. */
export function TargetPane({
  labId,
  level,
  progress,
  ui,
  inputs,
  setField,
  submit,
  result,
  succeeded,
  runId,
  onFire,
  browserTab,
  setBrowserTab,
  harborConnected,
  popoutNote,
  onPopout,
  carryNote,
}: Props) {
  const [scenarioOpen, setScenarioOpen] = useState(false);
  const scenario = SCENARIOS[labId];
  const browserTabs = ui.browserTabs ?? [{ id: "app", url: ui.url, title: ui.site }];

  return (
    <section className="wb-target" data-testid="pane-target">
      <div className="target-pane-bar">
        <div className="target-pane-heading">
          <p className="brief-kicker">Harbor · {scenario?.place ?? ui.site}</p>
          <h2>{scenario?.title ?? ui.site}</h2>
        </div>
        <button
          type="button"
          className="btn"
          aria-expanded={scenarioOpen}
          data-testid="scenario-toggle"
          onClick={() => setScenarioOpen((open) => !open)}
        >
          シナリオ
        </button>
        {harborConnected && (
          <span className="harbor-badge on" data-testid="harbor-link">
            Harbor 接続中
          </span>
        )}
        <button type="button" className="btn" onClick={onPopout}>
          別タブで開く
        </button>
      </div>
      {popoutNote && (
        <p className="popout-note" data-testid="popout-note">
          {popoutNote}
        </p>
      )}
      {carryNote && (
        <p className="carry-note" data-testid="carry-note">
          {carryNote}
        </p>
      )}
      {scenarioOpen && <LabBrief labId={labId} level={level} />}
      <div className="target-embed">
        <BrowserChrome tabs={browserTabs} activeTabId={browserTab} onTabChange={setBrowserTab}>
          <TargetApp labId={labId} browserTab={browserTab} progress={progress}>
            {ui.renderApp({
              inputs,
              setField,
              submit,
              result,
              succeeded,
              runId,
              onFire,
              level,
              browserTab,
              setBrowserTab,
            })}
          </TargetApp>
        </BrowserChrome>
      </div>
    </section>
  );
}
