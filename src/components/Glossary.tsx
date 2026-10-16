import { useState } from "react";
import { GLOSSARY } from "../glossary";
import { findLab } from "../labs";
import { RichText } from "./RichText";

export function Glossary() {
  const [query, setQuery] = useState("");
  const q = query.trim().toLowerCase();
  const terms = GLOSSARY.filter(
    (t) =>
      !q ||
      [t.term, ...(t.aliases ?? []), t.description].some((s) => s.toLowerCase().includes(q)),
  );

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>用語集</h1>
          <p className="page-lead">ラボやヒントに出てくる用語の解説です。わからない言葉があればここで確認できます。</p>
        </div>
      </div>

      <section className="pane">
        <div className="pane-head">
          <span className="pane-title">用語</span>
          <span className="pane-meta">{terms.length} 件</span>
        </div>
        <div className="glossary-search">
          <input
            type="search"
            value={query}
            placeholder="用語を検索（例: SameSite, エンコード）"
            aria-label="用語を検索"
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
        {terms.length === 0 ? (
          <div className="empty">該当する用語がありません。</div>
        ) : (
          <dl className="glossary">
            {terms.map((t) => (
              <div key={t.term} className="glossary-item">
                <dt>
                  {t.term}
                  {t.aliases && <span className="dim glossary-alias"> {t.aliases.join(" / ")}</span>}
                </dt>
                <dd>
                  <RichText text={t.description} />
                  {t.labs && (
                    <div className="glossary-labs">
                      {t.labs.map((id) => {
                        const lab = findLab(id);
                        return lab ? (
                          <a key={id} href={`#/lab/${id}`} className="tag">
                            {lab.meta.shortTitle}
                          </a>
                        ) : null;
                      })}
                    </div>
                  )}
                </dd>
              </div>
            ))}
          </dl>
        )}
      </section>
    </div>
  );
}
