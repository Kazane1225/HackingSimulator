import { useEffect, useRef } from "react";

const MESSAGE_TYPE = "hackme-xss-fired";

// Installed before the attacker's markup. The iframe is sandboxed with only
// allow-scripts (opaque origin), so payloads cannot touch the parent page;
// they can only report back through postMessage.
const HOOK = `<script>
(function () {
  function fire(m) { parent.postMessage({ type: "${MESSAGE_TYPE}", msg: String(m) }, "*"); }
  window.alert = fire;
  window.confirm = function (m) { fire(m); return true; };
  window.prompt = function (m) { fire(m); return ""; };
})();
</script>`;

const STYLE = `<style>
  body { font-family: system-ui, sans-serif; margin: 12px; color: #1f2937; background: #fff; }
  h3 { margin: 0 0 8px; font-size: 15px; }
  .guest-comment { border: 1px solid #d1d5db; border-radius: 6px; padding: 8px 10px; background: #f9fafb; word-break: break-all; }
</style>`;

interface Props {
  html: string;
  /** Bumped by the parent on every run so the iframe remounts fresh. */
  runId: number;
  onFire: (message: string) => void;
}

export function XssPreview({ html, runId, onFire }: Props) {
  const frameRef = useRef<HTMLIFrameElement>(null);

  useEffect(() => {
    const onMessage = (e: MessageEvent) => {
      if (e.source !== frameRef.current?.contentWindow) return;
      if (e.data && e.data.type === MESSAGE_TYPE) onFire(e.data.msg);
    };
    window.addEventListener("message", onMessage);
    return () => window.removeEventListener("message", onMessage);
  }, [onFire]);

  const doc = `<!doctype html><html><head><meta charset="utf-8">${STYLE}${HOOK}</head>
<body><h3>📖 ゲストブック</h3>${html}</body></html>`;

  return (
    <iframe
      key={runId}
      ref={frameRef}
      className="xss-frame"
      title="XSS プレビュー（サンドボックス）"
      sandbox="allow-scripts"
      srcDoc={doc}
    />
  );
}
