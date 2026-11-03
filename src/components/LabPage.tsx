import { Fragment, useCallback, useEffect, useRef, useState } from "react";
import { readDraft, readHints, removeDraft, writeDraft, writeHints } from "../drafts";
import type { AttackResult, Lab, LabField, LabInput, Level } from "../labs/types";
import { LEVELS } from "../labs/types";
import { readLoot, useLoot } from "../loot";
import { earlierMissionLabIds, HARBOR_MISSION } from "../missions";
import type { Progress } from "../progress";
import {
  buildLabRequest,
  executeLabRequest,
  formatRawRequest,
  formatRawResponse,
  judgeLabResponse,
  type HttpResponse,
} from "../realHttp";
import { useRealLabs } from "../realServer";
import { openTargetApp, targetChannel, type TargetState } from "../target/link";
import { Check, LabIcon, Lock, LockOpen, Play, Reset, Shield } from "./icons";
import { LAB_UI } from "./labUI";
import { RichText } from "./RichText";
import { RemediationPanel } from "./RemediationPanel";
import { TargetPane } from "./TargetPane";

type InspectorTab = "hint" | "source" | "solution" | "explain";

/** On narrow screens the three workbench panes are shown one at a time. */
type MobileTab = "target" | "proxy" | "inspector";
const MOBILE_TABS: { key: MobileTab; label: string }[] = [
  { key: "target", label: "状況" },
  { key: "proxy", label: "Proxy" },
  { key: "inspector", label: "ヒント・解説" },
];

interface Props {
  lab: Lab;
  progress: Progress;
  initialLevel?: Level;
  fromMission?: boolean;
  completedMissionStepIds: string[];
  isSolved: (labId: string, level: Level) => boolean;
  markSolved: (labId: string, level: Level) => void;
  remediationCompleted: boolean;
  markRemediated: (labId: string) => void;
}

interface Attempt {
  runId: number;
  at: number;
  level: Level;
  inputs: LabInput;
  status: string;
}

const RECORDED_STATUS = new Set(["成功", "失敗", "防御済み", "進展あり", "通常応答"]);

function attemptPreview(inputs: LabInput): string {
  const text = Object.entries(inputs)
    .filter(([, value]) => value !== "")
    .map(([key, value]) => `${key}=${value.replace(/\s+/g, " ")}`)
    .join(", ");
  return text.length > 48 ? `${text.slice(0, 48)}…` : text;
}

function inputDiff(older: LabInput, newer: LabInput): { key: string; left: string; right: string }[] {
  const keys = [...new Set([...Object.keys(older), ...Object.keys(newer)])].sort();
  return keys
    .filter((key) => (older[key] ?? "") !== (newer[key] ?? ""))
    .map((key) => ({ key, left: older[key] ?? "", right: newer[key] ?? "" }));
}

function carryMessage(labId: string, fromMission: boolean): string | null {
  const earlier = earlierMissionLabIds(labId);
  if (!fromMission || earlier.length === 0) return null;
  const found = readLoot().some((item) => earlier.includes(item.labId));
  return found
    ? "前の工程の戦利品を、Proxy の「持ち込んだ情報」に置いてあります。クリックでパラメータへ挿入できます。"
    : "前の工程の戦利品はまだありません。ラボを進めてから、もう一度ここを開くと挿入できます。";
}

function sameInputs(left: LabInput, right: LabInput): boolean {
  const keys = new Set([...Object.keys(left), ...Object.keys(right)]);
  for (const key of keys) {
    if ((left[key] ?? "") !== (right[key] ?? "")) return false;
  }
  return true;
}

function defaultInputs(lab: Lab): LabInput {
  return Object.fromEntries(lab.fields.filter((f) => !f.hidden).map((f) => [f.name, f.default ?? ""]));
}

function assembledDuplicatesOutput(assembled: string | undefined, output: string[]): boolean {
  const a = assembled?.trim() ?? "";
  if (!a) return true;
  return output.join("\n").includes(a);
}

export function LabPage({
  lab,
  progress,
  initialLevel,
  fromMission = false,
  completedMissionStepIds,
  isSolved,
  markSolved,
  remediationCompleted,
  markRemediated,
}: Props) {
  const id = lab.meta.id;
  const ui = LAB_UI[id];
  const firstUnsolved = LEVELS.find((lv) => lv < 5 && !isSolved(id, lv)) ?? 5;
  const startLevel = initialLevel ?? firstUnsolved;

  const [level, setLevel] = useState<Level>(startLevel);
  const [inputs, setInputs] = useState<LabInput>(() => readDraft(id, startLevel)?.inputs ?? defaultInputs(lab));
  const [result, setResult] = useState<AttackResult | null>(null);
  const [httpResponse, setHttpResponse] = useState<HttpResponse | null>(null);
  const [runId, setRunId] = useState(0);
  const [fired, setFired] = useState<string | null>(null);
  const [intercept, setIntercept] = useState(true);
  const [held, setHeld] = useState(false);
  const [inspector, setInspector] = useState<InspectorTab>("hint");
  const [hintsShown, setHintsShown] = useState<Partial<Record<Level, number>>>(() => readHints(id));
  const [mobileTab, setMobileTab] = useState<MobileTab>("target");
  const [revealed, setRevealed] = useState<string[]>(() => readDraft(id, startLevel)?.revealed ?? []);
  const [extraParams, setExtraParams] = useState<string[]>(() => readDraft(id, startLevel)?.extraParams ?? []);
  const [newParamName, setNewParamName] = useState("");
  const [focusField, setFocusField] = useState<string | null>(null);
  const [learningMode, setLearningMode] = useState<"attack" | "remediation">("attack");
  const [history, setHistory] = useState<Attempt[]>([]);
  const [compare, setCompare] = useState<number[]>([]);
  const [harborConnected, setHarborConnected] = useState(false);
  const [popoutNote, setPopoutNote] = useState<string | null>(null);
  const [carryNote] = useState<string | null>(() => carryMessage(id, fromMission));
  const { items: loot, ingest } = useLoot();

  const browserTabs = ui.browserTabs ?? [{ id: "app", url: ui.url, title: ui.site }];
  const [browserTab, setBrowserTab] = useState(browserTabs[0].id);

  const viaReal = useRealLabs().includes(id);
  // Bumped whenever the pending result is no longer wanted (new request, level change, reset).
  const requestSeq = useRef(0);
  const harborTimer = useRef<number | null>(null);

  useEffect(() => {
    const untouched = revealed.length === 0 && extraParams.length === 0 && sameInputs(inputs, defaultInputs(lab));
    if (untouched) removeDraft(id, level);
    else writeDraft(id, level, { inputs, revealed, extraParams });
  }, [id, lab, level, inputs, revealed, extraParams]);

  useEffect(() => {
    writeHints(id, hintsShown);
  }, [id, hintsShown]);

  const spec = lab.levels[level];
  const shownHints = Math.min(hintsShown[level] ?? 1, spec.hints.length);
  const solvedHere = isSolved(id, level);
  // Lv5 cannot be cleared; its write-up unlocks once Lv4 has been beaten.
  const solutionUnlocked = solvedHere || (level === 5 && isSolved(id, 4));
  const executionJudged = result?.renderHtml !== undefined;
  const succeeded = !!result && (executionJudged ? fired !== null : result.solved);
  const partial = !!result && !succeeded && !!result.progress;
  const benign = !!result && !succeeded && !!result.benign && !partial;

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
    const draft = readDraft(id, lv);
    setLevel(lv);
    if (draft) {
      setInputs(draft.inputs);
      setRevealed(draft.revealed);
      setExtraParams(draft.extraParams);
    } else {
      setRevealed([]);
      setExtraParams([]);
    }
    setNewParamName("");
    clear();
  };

  const restoreAttempt = (entry: Attempt) => {
    setLevel(entry.level);
    setInputs(entry.inputs);
    setRevealed(
      lab.fields
        .filter((field) => field.hidden && (entry.inputs[field.name] ?? "") !== "" && (entry.inputs[field.name] ?? "") !== (field.default ?? ""))
        .map((field) => field.name),
    );
    setExtraParams(Object.keys(entry.inputs).filter((name) => !lab.fields.some((field) => field.name === name)));
    setNewParamName("");
    clear();
  };

  const toggleCompare = (attemptId: number) => {
    setCompare((prev) => {
      if (prev.includes(attemptId)) return prev.filter((item) => item !== attemptId);
      return [...prev, attemptId].slice(-2);
    });
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
    const nextRun = runId + 1;
    setResult(r);
    setFired(null);
    setHeld(false);
    setRunId(nextRun);
    setHistory((prev) =>
      [{ runId: nextRun, at: Date.now(), level, inputs: { ...requestInputs }, status: "" }, ...prev].slice(0, 20),
    );
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

  const bridge = useRef({ setField, submitFromApp, setBrowserTab, onFire });
  bridge.current = { setField, submitFromApp, setBrowserTab, onFire };
  const snapshotRef = useRef<TargetState>({
    type: "state",
    labId: id,
    level,
    inputs,
    result,
    runId,
    fired,
    browserTab,
    succeeded,
  });
  snapshotRef.current = {
    type: "state",
    labId: id,
    level,
    inputs,
    result,
    runId,
    fired,
    browserTab,
    succeeded,
  };

  useEffect(() => {
    const channel = targetChannel();
    if (!channel) return;
    channel.onmessage = (ev: MessageEvent) => {
      const msg = ev.data as { type?: string; name?: string; value?: string; patch?: LabInput; id?: string; message?: string };
      if (!msg || typeof msg.type !== "string") return;
      if (msg.type === "hello" || msg.type === "ping") {
        setHarborConnected(true);
        setPopoutNote(null);
        window.clearTimeout(harborTimer.current ?? undefined);
        harborTimer.current = window.setTimeout(() => setHarborConnected(false), 5000);
        if (msg.type === "hello") channel.postMessage(snapshotRef.current);
      } else if (msg.type === "field" && typeof msg.name === "string") {
        bridge.current.setField(msg.name, msg.value ?? "");
      } else if (msg.type === "submit") {
        bridge.current.submitFromApp(msg.patch);
      } else if (msg.type === "tab" && typeof msg.id === "string") {
        bridge.current.setBrowserTab(msg.id);
      } else if (msg.type === "fire" && typeof msg.message === "string") {
        bridge.current.onFire(msg.message);
      }
    };
    channel.postMessage(snapshotRef.current);
    return () => {
      if (harborTimer.current !== null) window.clearTimeout(harborTimer.current);
      channel.close();
    };
  }, []);

  useEffect(() => {
    const channel = targetChannel();
    if (!channel) return;
    channel.postMessage(snapshotRef.current);
    channel.close();
  }, [id, level, inputs, result, runId, fired, browserTab, succeeded]);

  const labLoot = loot.filter((item) => item.labId === id);
  const carriedLoot = fromMission
    ? loot.filter((item) => earlierMissionLabIds(id).includes(item.labId))
    : [];
  const missionIndex = HARBOR_MISSION.findIndex((step) => step.requirement.labId === id && step.requirement.level === level);
  const missionStep = missionIndex >= 0 ? HARBOR_MISSION[missionIndex] : undefined;
  const missionUnlocked = missionIndex === 0 || (missionIndex > 0 && completedMissionStepIds.includes(HARBOR_MISSION[missionIndex - 1].id));
  const missionRecorded = !!missionStep && completedMissionStepIds.includes(missionStep.id);
  const missionLootReady =
    !!missionStep &&
    (!missionStep.requirement.lootId ||
      labLoot.some((item) => item.id === missionStep.requirement.lootId) ||
      (result?.loot ?? []).some((item) => item.id === missionStep.requirement.lootId));
  const compared = compare
    .map((attemptId) => history.find((entry) => entry.runId === attemptId))
    .filter((entry): entry is Attempt => entry !== undefined)
    .sort((a, b) => a.at - b.at);
  const diffs = compared.length === 2 ? inputDiff(compared[0].inputs, compared[1].inputs) : [];

  const insertLoot = (value: string) => {
    const target = focusField ?? visibleFields[0]?.name;
    if (target) setField(target, value);
    void navigator.clipboard?.writeText(value).catch(() => undefined);
  };

  const popOut = () => {
    if (openTargetApp()) {
      setPopoutNote(null);
      return;
    }
    setPopoutNote("ポップアップがブロックされました。この画面のアプリから操作できます。");
  };

  const status = held
    ? { cls: "held", label: "傍受中" }
    : !result
      ? { cls: "idle", label: "待機" }
      : succeeded
        ? { cls: "ok", label: "成功" }
        : level === 5
          ? { cls: "blocked", label: "防御済み" }
          : partial
            ? { cls: "progress", label: "進展あり" }
            : benign
              ? { cls: "benign", label: "通常応答" }
              : { cls: "ng", label: "失敗" };

  useEffect(() => {
    if (!result || !RECORDED_STATUS.has(status.label)) return;
    setHistory((prev) =>
      prev.map((entry) => (entry.runId === runId && entry.status !== status.label ? { ...entry, status: status.label } : entry)),
    );
  }, [result, runId, status.label]);

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
        <div className="segmented lab-mode-switch" role="tablist" aria-label="学習モード">
          <button role="tab" aria-selected={learningMode === "attack"} className={`seg ${learningMode === "attack" ? "active" : ""}`} onClick={() => setLearningMode("attack")}>
            攻撃演習
          </button>
          <button role="tab" aria-selected={learningMode === "remediation"} className={`seg ${learningMode === "remediation" ? "active" : ""}`} onClick={() => setLearningMode("remediation")} data-testid="remediation-tab">
            {remediationCompleted && <Check width={13} height={13} />} 修正演習
          </button>
        </div>
        {learningMode === "attack" && <div className="segmented" role="tablist" aria-label="セキュリティレベル">
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
        </div>}
      </div>

      {learningMode === "remediation" ? (
        <RemediationPanel
          lab={lab}
          completed={remediationCompleted}
          onComplete={() => markRemediated(id)}
          isSolved={(lv) => isSolved(id, lv)}
        />
      ) : <><div className="defense-bar">
        <span className="defense-tag mono">防御 Lv{level}</span>
        <span>{spec.defense}</span>
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
        <TargetPane
          labId={id}
          level={level}
          progress={progress}
          ui={ui}
          inputs={inputs}
          setField={setField}
          submit={submitFromApp}
          result={result}
          succeeded={succeeded}
          runId={runId}
          onFire={onFire}
          browserTab={browserTab}
          setBrowserTab={setBrowserTab}
          harborConnected={harborConnected}
          popoutNote={popoutNote}
          onPopout={popOut}
          carryNote={carryNote}
        />

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
              {carriedLoot.length > 0 && (
                <div className="loot carried-loot" data-testid="carried-loot">
                  <div className="loot-label mono">持ち込んだ情報</div>
                  <p className="dim loot-hint">前の工程で見つけた値です。クリックでフォーカス中のパラメータへ挿入します。</p>
                  <div className="loot-list">
                    {carriedLoot.map((item) => (
                      <button
                        key={`${item.labId}-${item.id}`}
                        type="button"
                        className="loot-chip"
                        title={item.value}
                        onClick={() => insertLoot(item.value)}
                      >
                        <span className="loot-chip-lab">{item.label}</span>
                        <span className="loot-chip-val mono">{item.value}</span>
                      </button>
                    ))}
                  </div>
                </div>
              )}
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
                    {succeeded && level < 5 && <div className="notice-strong">Lv{level} クリア — 「解答」タブが解放されました</div>}
                    {succeeded && (
                      <div className="next-actions">
                        {level < 5 && (
                          <button
                            type="button"
                            className="btn"
                            onClick={() => {
                              setInspector("solution");
                              setMobileTab("inspector");
                            }}
                          >
                            解答を読む
                          </button>
                        )}
                        {level < 4 && (
                          <button type="button" className="btn btn-accent" onClick={() => selectLevel((level + 1) as Level)}>
                            次のレベルへ
                          </button>
                        )}
                        {level === 4 && (
                          <>
                            <button type="button" className="btn" onClick={() => selectLevel(5)}>
                              Lv5 を見る
                            </button>
                            <button type="button" className="btn btn-accent" onClick={() => setLearningMode("remediation")}>
                              修正演習へ
                            </button>
                          </>
                        )}
                        {missionStep && missionLootReady && missionUnlocked && !missionRecorded && (
                          <a className="btn" href="#/mission">
                            ミッションで証拠を記録
                          </a>
                        )}
                      </div>
                    )}
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
                          onClick={() => insertLoot(item.value)}
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
            {history.length > 0 && (
              <div className="history" data-testid="request-history">
                <div className="history-head">
                  <span className="pane-title">履歴</span>
                  <span className="dim">2件選ぶと差分を表示します</span>
                </div>
                {history.map((entry) => {
                  const preview = attemptPreview(entry.inputs);
                  const when = new Date(entry.at).toLocaleTimeString("ja-JP", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
                  return (
                    <div key={entry.runId} className="history-row">
                      <input
                        type="checkbox"
                        checked={compare.includes(entry.runId)}
                        aria-label={`${when} を比較`}
                        onChange={() => toggleCompare(entry.runId)}
                      />
                      <button type="button" className="history-restore" onClick={() => restoreAttempt(entry)}>
                        <span className="mono">{when}</span>
                        <span>Lv{entry.level}</span>
                        <span>{entry.status || "送信済み"}</span>
                        <span className="history-preview mono">{preview}</span>
                      </button>
                    </div>
                  );
                })}
                {diffs.length > 0 && (
                  <div className="history-diff" data-testid="request-diff">
                    {diffs.map((row) => (
                      <div key={row.key} className="history-diff-row">
                        <span className="mono">{row.key}</span>
                        <span className="mono history-diff-old">{row.left || "（空）"}</span>
                        <span className="mono history-diff-new">{row.right || "（空）"}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
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
                  {lab.meta.standards.cves && lab.meta.standards.cves.length > 0 && (
                    <>
                      <div className="meta-title">実在するCVE事例</div>
                      <div className="cve-list" data-testid="cve-list">
                        {lab.meta.standards.cves.map((cve) => (
                          <article className="cve-card" key={cve.id}>
                            <div className="cve-card-head">
                              <a href={cve.url} target="_blank" rel="noopener noreferrer" className="mono">
                                {cve.id}
                              </a>
                              <span className="cve-relation">
                                {cve.relation === "direct" ? "同じ攻撃メカニズム" : "同じ弱点クラスの事例"}
                              </span>
                            </div>
                            <strong>{cve.title}</strong>
                            <p>{cve.summary}</p>
                          </article>
                        ))}
                      </div>
                    </>
                  )}
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
      </div></>}
    </div>
  );
}
