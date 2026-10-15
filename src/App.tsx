import { useEffect, useState } from "react";
import { Home } from "./components/Home";
import { LabPage } from "./components/LabPage";
import { findLab } from "./labs";
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

  const labMatch = route.match(/^\/lab\/([\w-]+)/);
  const lab = labMatch ? findLab(labMatch[1]) : undefined;

  useEffect(() => {
    window.scrollTo(0, 0);
  }, [route]);

  return (
    <div className="app">
      <header className="topbar">
        <a href="#/" className="brand">
          <span className="brand-mark">&gt;_</span> HackMe
          <span className="brand-sub">セキュリティ学習シミュレータ</span>
        </a>
        <nav>
          <a href="#/">ラボ一覧</a>
        </nav>
      </header>

      <main className="content">
        {lab ? (
          <LabPage key={lab.meta.id} lab={lab} isSolved={isSolved} markSolved={markSolved} />
        ) : (
          <Home progress={progress} onReset={reset} />
        )}
      </main>

      <footer className="footer">
        すべての「脆弱なサーバー」はブラウザ内でシミュレートされています。実在のシステムへの攻撃は違法です。
        学んだ技術は、許可された環境でのみ使用してください。
      </footer>
    </div>
  );
}
