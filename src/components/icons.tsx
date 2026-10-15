import type { SVGProps } from "react";

type IconProps = SVGProps<SVGSVGElement>;

const base = (props: IconProps): IconProps => ({
  width: 20,
  height: 20,
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.7,
  strokeLinecap: "round",
  strokeLinejoin: "round",
  ...props,
});

/** Brand logo: a bracket-wrapped target reticle. */
export function Logo(props: IconProps) {
  return (
    <svg {...base({ ...props, strokeWidth: 1.8 })}>
      <path d="M7 4H5a1 1 0 0 0-1 1v14a1 1 0 0 0 1 1h2" />
      <path d="M17 4h2a1 1 0 0 1 1 1v14a1 1 0 0 1-1 1h-2" />
      <circle cx="12" cy="12" r="3.2" />
      <path d="M12 6.5V8M12 16v1.5M6.5 12H8M16 12h1.5" />
    </svg>
  );
}

function Database(props: IconProps) {
  return (
    <svg {...base(props)}>
      <ellipse cx="12" cy="5.5" rx="7" ry="2.8" />
      <path d="M5 5.5v6c0 1.55 3.13 2.8 7 2.8s7-1.25 7-2.8v-6" />
      <path d="M5 11.5v6c0 1.55 3.13 2.8 7 2.8s7-1.25 7-2.8v-6" />
    </svg>
  );
}

function CodeBug(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="m8 7-4 5 4 5" />
      <path d="m16 7 4 5-4 5" />
      <path d="M13.5 6 10.5 18" />
    </svg>
  );
}

function Terminal(props: IconProps) {
  return (
    <svg {...base(props)}>
      <rect x="3" y="4" width="18" height="16" rx="2" />
      <path d="m7 9 3 3-3 3" />
      <path d="M13 15h4" />
    </svg>
  );
}

function Folder(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="M3 7a2 2 0 0 1 2-2h4l2 2.5h8a2 2 0 0 1 2 2V18a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />
      <path d="M12 11v5M9.5 13.5 12 11l2.5 2.5" />
    </svg>
  );
}

function Bank(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="M3 9.5 12 4l9 5.5" />
      <path d="M5 10v7M9.5 10v7M14.5 10v7M19 10v7" />
      <path d="M3.5 20h17" />
    </svg>
  );
}

const LAB_ICONS: Record<string, (p: IconProps) => JSX.Element> = {
  sqli: Database,
  xss: CodeBug,
  cmdi: Terminal,
  path: Folder,
  csrf: Bank,
};

export function LabIcon({ id, ...props }: { id: string } & IconProps) {
  const Cmp = LAB_ICONS[id] ?? Terminal;
  return <Cmp {...props} />;
}

export function Check(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="m4.5 12.5 5 5 10-11" />
    </svg>
  );
}

export function Lock(props: IconProps) {
  return (
    <svg {...base(props)}>
      <rect x="5" y="10.5" width="14" height="9.5" rx="2" />
      <path d="M8 10.5V7.5a4 4 0 0 1 8 0v3" />
    </svg>
  );
}

export function Shield(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="M12 3.5 5 6v5.5c0 4.2 2.9 7.5 7 9 4.1-1.5 7-4.8 7-9V6z" />
      <path d="m9 12 2 2 4-4.5" />
    </svg>
  );
}

export function Play(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="M7 5.5v13l11-6.5z" />
    </svg>
  );
}

export function Reload(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="M20 11a8 8 0 1 0-.9 4.5" />
      <path d="M20 5v5h-5" />
    </svg>
  );
}

export function Reset(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="M4 12a8 8 0 1 0 2.3-5.6" />
      <path d="M4 4v4h4" />
    </svg>
  );
}

export function ArrowLeft(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="M19 12H5M11 6l-6 6 6 6" />
    </svg>
  );
}

export function ChevronRight(props: IconProps) {
  return (
    <svg {...base(props)}>
      <path d="m9 6 6 6-6 6" />
    </svg>
  );
}

export function LockOpen(props: IconProps) {
  return (
    <svg {...base(props)}>
      <rect x="5" y="10.5" width="14" height="9.5" rx="2" />
      <path d="M8 10.5V7.5a4 4 0 0 1 7.5-1.9" />
    </svg>
  );
}
