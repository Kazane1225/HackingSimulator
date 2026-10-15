import { LABS } from "../labs";
import { LEVELS } from "../labs/types";
import type { Progress } from "../progress";

interface Props {
  progress: Progress;
  onReset: () => void;
}

export function Home({ progress, onReset }: Props) {
  const total = LABS.length * 4;
  const cleared = LABS.reduce(
    (sum, lab) => sum + (progress[lab.meta.id] ?? []).filter((l) => l <= 4).length,
    0,
  );

  return (
    <div className="home">
      <section className="hero">
        <h1>攻撃者の視点で、守り方を学ぶ。</h1>
        <p>
          HackMe は Web の代表的な脆弱性を安全に体験できる学習用シミュレータです。各ラボには
          5 段階のセキュリティレベルがあり、Lv1〜4 は少しずつ強化される「不完全な防御」、Lv5
          は突破不可能な「正しい実装」です。ヒントはいつでも、解答はクリア後に見られます。
        </p>
        <div className="hero-stats">
          <span>
            クリア <strong>{cleared}</strong> / {total}
          </span>
          <button className="btn-ghost" onClick={onReset} disabled={cleared === 0}>
            進捗をリセット
          </button>
        </div>
      </section>

      <section className="howto">
        <h2>遊び方</h2>
        <ol>
          <li>ラボを選び、レベル（Lv1〜5）を選ぶ</li>
          <li>「サーバー側コード」を読んで防御の穴を探す（行き詰まったらヒント）</li>
          <li>ペイロードを入力して攻撃を実行し、目標を達成する</li>
          <li>クリアしたら解答と解説で、なぜ刺さったのか・どう防ぐのかを確認する</li>
        </ol>
      </section>

      <section className="lab-grid">
        {LABS.map((lab) => {
          const solved = progress[lab.meta.id] ?? [];
          return (
            <a key={lab.meta.id} className="lab-card" href={`#/lab/${lab.meta.id}`}>
              <div className="lab-card-head">
                <span className="lab-icon">{lab.meta.icon}</span>
                <span className="lab-category">{lab.meta.category}</span>
              </div>
              <h3>{lab.meta.shortTitle}</h3>
              <p>{lab.meta.summary}</p>
              <div className="level-pips" aria-label="クリア状況">
                {LEVELS.map((lv) => (
                  <span
                    key={lv}
                    className={`pip ${solved.includes(lv) ? "pip-done" : ""} ${lv === 5 ? "pip-lock" : ""}`}
                    title={lv === 5 ? "Lv5: 正しい実装（突破不可）" : `Lv${lv}`}
                  >
                    {lv === 5 ? "🛡" : lv}
                  </span>
                ))}
              </div>
            </a>
          );
        })}
      </section>
    </div>
  );
}
