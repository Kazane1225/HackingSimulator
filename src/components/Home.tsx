import { COVERAGE_LABEL, LEARNING_TRACKS, OWASP_TOP10_2021 } from "../curriculum";
import { findLab, LABS } from "../labs";
import { LEVELS } from "../labs/types";
import type { Progress } from "../progress";
import { Check, LabIcon, Reset, Shield } from "./icons";

interface Props {
  progress: Progress;
  onReset: () => void;
}

function solvedLevels(progress: Progress, labId: string): number[] {
  return progress[labId] ?? [];
}

export function Home({ progress, onReset }: Props) {
  const anySolved = LABS.some((lab) => solvedLevels(progress, lab.meta.id).length > 0);
  const covered = OWASP_TOP10_2021.filter((c) => c.coverage === "covered").length;
  const adjacent = OWASP_TOP10_2021.filter((c) => c.coverage === "adjacent").length;
  const missing = OWASP_TOP10_2021.filter((c) => c.coverage === "none").length;

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>ダッシュボード</h1>
          <p className="page-lead">
            Web の代表的な脆弱性を、攻撃者の視点で安全に体験する学習用シミュレータです。脆弱なサーバーはすべてブラウザ内で動作します。上から順に進めると、理解が積み上がります。
          </p>
        </div>
        <button className="btn" onClick={onReset} disabled={!anySolved}>
          <Reset width={14} height={14} /> 進捗をリセット
        </button>
      </div>

      <section className="pane" data-testid="owasp-map">
        <div className="pane-head">
          <span className="pane-title">OWASP Top 10:2021</span>
          <span className="pane-meta">
            カバー {covered} / 隣接 {adjacent} / 未対応 {missing}
          </span>
        </div>
        <div className="owasp-map">
          {OWASP_TOP10_2021.map((cat) => {
            const first = cat.labIds[0];
            const inner = (
              <>
                <span className="owasp-code mono">{cat.code}</span>
                <span className="owasp-name">{cat.name}</span>
                <span className={`owasp-tag ${cat.coverage}`}>{COVERAGE_LABEL[cat.coverage]}</span>
              </>
            );
            return first ? (
              <a
                key={cat.code}
                href={`#/lab/${first}`}
                className={`owasp-cell ${cat.coverage}`}
                title={cat.note ?? cat.yearCode}
              >
                {inner}
              </a>
            ) : (
              <div key={cat.code} className={`owasp-cell ${cat.coverage}`} title={cat.note ?? cat.yearCode}>
                {inner}
              </div>
            );
          })}
        </div>
        <p className="owasp-legend">
          10 個のラボは A01 / A03 / A07 / A10 を厚く扱います。A04 はアップロードで隣接、A02・A05・A06・A08・A09 は未対応です。
        </p>
      </section>

      {LEARNING_TRACKS.map((track) => {
        const trackCleared = track.labIds.reduce((sum, id) => {
          return sum + solvedLevels(progress, id).filter((lv) => lv <= 4).length;
        }, 0);
        return (
          <section key={track.id} className="pane track-pane" data-testid={`track-${track.id}`}>
            <div className="pane-head">
              <span className="pane-title">
                <span className="track-step mono">{track.step}</span>
                {track.title}
              </span>
              <span className="pane-meta">
                {track.summary} · {trackCleared}/{track.labIds.length * 4}
              </span>
            </div>
            <table className="lab-table">
              <thead>
                <tr>
                  <th>ラボ</th>
                  <th>目標</th>
                  {LEVELS.map((lv) => (
                    <th key={lv} className="lv-col">
                      Lv{lv}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {track.labIds.map((id) => {
                  const lab = findLab(id);
                  if (!lab) return null;
                  const solved = solvedLevels(progress, id);
                  return (
                    <tr key={id} onClick={() => (window.location.hash = `#/lab/${id}`)}>
                      <td>
                        <a href={`#/lab/${id}`} className="lab-name">
                          <LabIcon id={id} width={16} height={16} />
                          {lab.meta.shortTitle}
                        </a>
                      </td>
                      <td className="dim objective-cell">{lab.meta.objective}</td>
                      {LEVELS.map((lv) => (
                        <td key={lv} className="lv-col">
                          {lv === 5 ? (
                            <Shield width={15} height={15} className="lv-impossible" aria-label="正しい実装（突破不可）" />
                          ) : solved.includes(lv) ? (
                            <Check width={15} height={15} className="lv-done" aria-label="クリア" />
                          ) : (
                            <span className="lv-todo" aria-label="未クリア" />
                          )}
                        </td>
                      ))}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </section>
        );
      })}

      <div className="pane-row">
        <section className="pane">
          <div className="pane-head">
            <span className="pane-title">進め方</span>
          </div>
          <ol className="steps">
            <li>上の推奨順でラボを選ぶ。Lv1〜4 は少しずつ強化される不完全な防御です。</li>
            <li>標的アプリは普段の利用者として操作し、owner や role などの改ざんは Proxy で行います。</li>
            <li>「ソース」タブでサーバー側の処理を読み、防御の穴を探す。詰まったら「ヒント」を 1 段ずつ開く。</li>
            <li>
              クリア後に解答と解説を読み、なぜ通ったのか・どう防ぐのかを確認する。わからない用語は
              <a href="#/glossary">用語集</a>で確認する。
            </li>
          </ol>
        </section>
        <section className="pane">
          <div className="pane-head">
            <span className="pane-title">レベルについて</span>
          </div>
          <dl className="kv">
            <dt>Lv1</dt>
            <dd>防御なし</dd>
            <dt>Lv2〜4</dt>
            <dd>不完全な防御。前のレベルの手口は通用しません</dd>
            <dt>Lv5</dt>
            <dd>正しい実装（突破不可）。なぜ安全かを学ぶレベルです</dd>
            <dt>ヒント</dt>
            <dd>ヒントは 3 段階（Lv5 は 2 段階）で、必要なぶんだけ開けます。解答はクリア後に解放されます</dd>
          </dl>
        </section>
      </div>
    </div>
  );
}
