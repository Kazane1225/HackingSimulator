import { useEffect, useState } from "react";
import { Glossary } from "./components/Glossary";
import { Home } from "./components/Home";
import { LabPage } from "./components/LabPage";
import { MissionPage } from "./components/MissionPage";
import { Sidebar } from "./components/Sidebar";
import { StoreWindow } from "./components/StoreWindow";
import { Logo } from "./components/icons";
import { clearDrafts, clearHints } from "./drafts";
import { LABS, findLab } from "./labs";
import type { Level } from "./labs/types";
import { useLearningProgress } from "./learningProgress";
import { useLoot } from "./loot";
import { useProgress } from "./progress";

interface Route {
  path: string;
  level?: Level;
  fromMission: boolean;
}

/** Hash-based routing so deep links work on GitHub Pages without a 404 shim. */
function useHashRoute(): Route {
  const [hash, setHash] = useState(() => window.location.hash);
  useEffect(() => {
    const onChange = () => setHash(window.location.hash);
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  const raw = hash.replace(/^#/, "") || "/";
  const queryAt = raw.indexOf("?");
  const path = queryAt === -1 ? raw : raw.slice(0, queryAt);
  const params = new URLSearchParams(queryAt === -1 ? "" : raw.slice(queryAt + 1));
  const level = Number(params.get("lv"));
  return {
    path: path || "/",
    level: level === 1 || level === 2 || level === 3 || level === 4 || level === 5 ? level : undefined,
    fromMission: params.get("from") === "mission",
  };
}

export function App() {
  const route = useHashRoute();
  const { progress, markSolved, isSolved, reset, replace } = useProgress();
  const { learningProgress, markRemediated, completeMissionStep, resetLearning, replaceLearning } = useLearningProgress();
  const { items: loot, reset: resetLoot, replace: replaceLoot } = useLoot();

  const labMatch = route.path.match(/^\/lab\/([\w-]+)/);
  const lab = labMatch ? findLab(labMatch[1]) : undefined;

  if (route.path === "/app") return <StoreWindow progress={progress} />;

  const total = LABS.length * 4;
  const cleared = LABS.reduce(
    (sum, l) => sum + (progress[l.meta.id] ?? []).filter((lv) => lv <= 4).length,
    0,
  );

  return (
    <div className="shell">
      <header className="titlebar">
        <a href="#/" className="brand">
          <Logo width={18} height={18} className="brand-logo" />
          <span className="brand-name">HackLab</span>
        </a>
        <span className="titlebar-sep" />
        <span className="titlebar-path">
          {lab ? (
            <>
              <a href="#/">ラボ</a>
              <span className="crumb-sep">/</span>
              <span>{lab.meta.shortTitle}</span>
            </>
          ) : route.path === "/glossary" ? (
            <span>用語集</span>
          ) : route.path === "/mission" ? (
            <span>Harbor侵害調査</span>
          ) : (
            <span>ダッシュボード</span>
          )}
        </span>
        <span className="titlebar-spacer" />
        <span className="titlebar-progress" title="Lv1〜4 のクリア数">
          <span className="meter">
            <span className="meter-fill" style={{ width: `${(cleared / total) * 100}%` }} />
          </span>
          <span className="mono">
            {cleared}/{total}
          </span>
        </span>
      </header>

      <div className="workspace">
        <Sidebar
          activeId={lab?.meta.id}
          progress={progress}
          glossaryActive={route.path === "/glossary"}
          missionActive={route.path === "/mission"}
        />
        <main className="main">
          {lab ? (
            <LabPage
              key={lab.meta.id}
              lab={lab}
              progress={progress}
              initialLevel={route.level}
              fromMission={route.fromMission}
              isSolved={isSolved}
              markSolved={markSolved}
              remediationCompleted={learningProgress.remediatedLabIds.includes(lab.meta.id)}
              markRemediated={markRemediated}
            />
          ) : route.path === "/glossary" ? (
            <Glossary />
          ) : route.path === "/mission" ? (
            <MissionPage
              progress={progress}
              learningProgress={learningProgress}
              completeStep={completeMissionStep}
            />
          ) : (
            <Home
              progress={progress}
              remediatedCount={learningProgress.remediatedLabIds.length}
              lootCount={loot.length}
              onReset={() => {
                reset();
                resetLearning();
                resetLoot();
                clearDrafts();
                clearHints();
              }}
              onExport={() => {
                const payload = { progress, learning: learningProgress, loot };
                const file = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
                const link = document.createElement("a");
                link.href = URL.createObjectURL(file);
                link.download = "hacklab-progress.json";
                link.click();
                URL.revokeObjectURL(link.href);
              }}
              onImport={(data) => {
                if (!data || typeof data !== "object" || Array.isArray(data)) return false;
                const row = data as Record<string, unknown>;
                if (!("progress" in row) && !("learning" in row) && !("loot" in row)) return false;
                if ("progress" in row) replace(row.progress);
                if ("learning" in row) replaceLearning(row.learning);
                if ("loot" in row) replaceLoot(row.loot);
                return true;
              }}
            />
          )}
        </main>
      </div>

      <footer className="statusbar">
        <span className="status-item">
          <span className="status-dot" /> 隔離された学習環境 — 外部への通信なし
        </span>
        <span className="titlebar-spacer" />
        <span className="status-item">許可された環境以外での攻撃は違法です</span>
      </footer>
    </div>
  );
}
