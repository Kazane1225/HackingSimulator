import { LABS } from "../labs";
import { LEVELS } from "../labs/types";
import type { Progress } from "../progress";
import { LabIcon } from "./icons";

interface Props {
  activeId?: string;
  progress: Progress;
}

export function Sidebar({ activeId, progress }: Props) {
  return (
    <aside className="sidebar">
      <div className="sidebar-section">ラボ</div>
      <nav>
        {LABS.map((lab) => {
          const solved = progress[lab.meta.id] ?? [];
          const count = solved.filter((lv) => lv <= 4).length;
          return (
            <a
              key={lab.meta.id}
              href={`#/lab/${lab.meta.id}`}
              className={`side-item ${lab.meta.id === activeId ? "active" : ""}`}
            >
              <LabIcon id={lab.meta.id} width={16} height={16} className="side-icon" />
              <span className="side-label">{lab.meta.shortTitle}</span>
              <span className="side-levels" aria-label={`${count} / 4 クリア`}>
                {LEVELS.slice(0, 4).map((lv) => (
                  <i key={lv} className={solved.includes(lv) ? "on" : ""} />
                ))}
              </span>
            </a>
          );
        })}
      </nav>
    </aside>
  );
}
