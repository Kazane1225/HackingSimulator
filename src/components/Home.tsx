import { LABS } from "../labs";
import { LEVELS } from "../labs/types";
import type { Progress } from "../progress";
import { Check, LabIcon, Reset, Shield } from "./icons";

interface Props {
  progress: Progress;
  onReset: () => void;
}

export function Home({ progress, onReset }: Props) {
  const anySolved = LABS.some((lab) => (progress[lab.meta.id] ?? []).length > 0);

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>ダッシュボード</h1>
          <p className="page-lead">
            Web の代表的な脆弱性を、攻撃者の視点で安全に体験する学習用シミュレータです。脆弱なサーバーはすべてブラウザ内で動作します。
          </p>
        </div>
        <button className="btn" onClick={onReset} disabled={!anySolved}>
          <Reset width={14} height={14} /> 進捗をリセット
        </button>
      </div>

      <section className="pane">
        <div className="pane-head">
          <span className="pane-title">ラボ</span>
          <span className="pane-meta">{LABS.length} 件</span>
        </div>
        <table className="lab-table">
          <thead>
            <tr>
              <th>ラボ</th>
              <th>分類</th>
              <th>目標</th>
              {LEVELS.map((lv) => (
                <th key={lv} className="lv-col">
                  Lv{lv}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {LABS.map((lab) => {
              const solved = progress[lab.meta.id] ?? [];
              return (
                <tr key={lab.meta.id} onClick={() => (window.location.hash = `#/lab/${lab.meta.id}`)}>
                  <td>
                    <a href={`#/lab/${lab.meta.id}`} className="lab-name">
                      <LabIcon id={lab.meta.id} width={16} height={16} />
                      {lab.meta.shortTitle}
                    </a>
                  </td>
                  <td className="dim">{lab.meta.category}</td>
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

      <div className="pane-row">
        <section className="pane">
          <div className="pane-head">
            <span className="pane-title">進め方</span>
          </div>
          <ol className="steps">
            <li>ラボとレベルを選ぶ。Lv1〜4 は少しずつ強化される不完全な防御です。</li>
            <li>「ソース」タブでサーバー側の処理を読み、防御の穴を探す。</li>
            <li>リクエストを組み立てて送信し、目標を達成する。</li>
            <li>クリア後に解答と解説を読み、なぜ通ったのか・どう防ぐのかを確認する。</li>
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
            <dd>いつでも閲覧可。解答はクリア後に解放されます</dd>
          </dl>
        </section>
      </div>
    </div>
  );
}
