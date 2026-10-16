import { LEARNING_TRACKS } from "../curriculum";
import { findLab } from "../labs";
import { LEVELS } from "../labs/types";
import type { Progress } from "../progress";
import { LabIcon } from "./icons";

interface Props {
  activeId?: string;
  progress: Progress;
  glossaryActive?: boolean;
}

export function Sidebar({ activeId, progress, glossaryActive }: Props) {
  return (
    <aside className="sidebar">
      {LEARNING_TRACKS.map((track) => (
        <div key={track.id}>
          <div className="sidebar-section">
            {track.step}. {track.title}
          </div>
          <nav>
            {track.labIds.map((id) => {
              const lab = findLab(id);
              if (!lab) return null;
              const solved = progress[id] ?? [];
              const count = solved.filter((lv) => lv <= 4).length;
              return (
                <a
                  key={id}
                  href={`#/lab/${id}`}
                  className={`side-item ${id === activeId ? "active" : ""}`}
                >
                  <LabIcon id={id} width={16} height={16} className="side-icon" />
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
        </div>
      ))}
      <div className="sidebar-section">学習資料</div>
      <nav>
        <a href="#/glossary" className={`side-item ${glossaryActive ? "active" : ""}`}>
          <span className="side-label">用語集</span>
        </a>
      </nav>
    </aside>
  );
}
