import { Fragment } from "react";

/** Render `inline code` spans within a line of text. */
function renderInline(text: string) {
  const parts = text.split(/(`[^`]+`)/g);
  return parts.map((part, i) =>
    part.startsWith("`") && part.endsWith("`") && part.length > 1 ? (
      <code key={i}>{part.slice(1, -1)}</code>
    ) : (
      <Fragment key={i}>{part}</Fragment>
    ),
  );
}

/**
 * Minimal text formatter for the teaching content: blank lines separate
 * paragraphs, single newlines become line breaks, backticks become <code>.
 * Everything is rendered as React text nodes, so content is never parsed as HTML.
 */
export function RichText({ text }: { text: string }) {
  const paragraphs = text.trim().split(/\n\s*\n/);
  return (
    <div className="rich">
      {paragraphs.map((p, i) => (
        <p key={i}>
          {p.split("\n").map((line, j) => (
            <Fragment key={j}>
              {j > 0 && <br />}
              {renderInline(line)}
            </Fragment>
          ))}
        </p>
      ))}
    </div>
  );
}
