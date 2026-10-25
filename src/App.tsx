import { useEffect, useState } from "react";
import { Glossary } from "./components/Glossary";
import { Home } from "./components/Home";
import { LabPage } from "./components/LabPage";
import { MissionPage } from "./components/MissionPage";
import { Sidebar } from "./components/Sidebar";
import { StoreWindow } from "./components/StoreWindow";
import { Logo } from "./components/icons";
import { LABS, findLab } from "./labs";
import { useLearningProgress } from "./learningProgress";
import { useProgress } from "./progress";

/** Hash-based routing so deep links work on GitHub Pages without a 404 shim. */
function useHashRoute(): string {
  const [hash, setHash] = useState(() => window.location.hash);
  useEffect(() => {
    const onChange = () => setHash(window.location.hash);
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return hash.replace(/^#/, "") || "/";
}

export function App() {
  const route = useHashRoute();
  const { progress, markSolved, isSolved, reset } = useProgress();
  const { learningProgress, markRemediated, completeMissionStep, resetLearning } = useLearningProgress();

  const labMatch = route.match(/^\/lab\/([\w-]+)/);
  const lab = labMatch ? findLab(labMatch[1]) : undefined;

  if (route === "/app") return <StoreWindow progress={progress} />;

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
          ) : route === "/glossary" ? (
            <span>用語集</span>
          ) : route === "/mission" ? (
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
          glossaryActive={route === "/glossary"}
          missionActive={route === "/mission"}
        />
        <main className="main">
          {lab ? (
            <LabPage
              key={lab.meta.id}
              lab={lab}
              isSolved={isSolved}
              markSolved={markSolved}
              remediationCompleted={learningProgress.remediatedLabIds.includes(lab.meta.id)}
              markRemediated={markRemediated}
            />
          ) : route === "/glossary" ? (
            <Glossary />
          ) : route === "/mission" ? (
            <MissionPage
              progress={progress}
              learningProgress={learningProgress}
              completeStep={completeMissionStep}
            />
          ) : (
            <Home
              progress={progress}
              remediatedCount={learningProgress.remediatedLabIds.length}
              onReset={() => {
                reset();
                resetLearning();
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
