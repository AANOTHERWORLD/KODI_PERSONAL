"use client";

import { createContext, useContext, useId, useState, type ReactNode } from "react";
import type { LensId } from "@/content/types";
import { lenses } from "@/content/lenses";
import { debug } from "@/lib/debug";

// Compact lens key for Home. Activating a lens (hover, focus, or tap) highlights the
// selected-work entries that demonstrate it and dims the others. Works by keyboard and touch,
// announces state to screen readers, and degrades to a static list without JavaScript
// (the buttons render as plain text and entries stay fully visible).

type LensState = { active: LensId | null; setActive: (l: LensId | null) => void };
const LensContext = createContext<LensState>({ active: null, setActive: () => {} });

export function HomeLensProvider({ children }: { children: ReactNode }) {
  const [active, setActive] = useState<LensId | null>(null);
  return <LensContext.Provider value={{ active, setActive }}>{children}</LensContext.Provider>;
}

export function LensAwareEntry({ lensIds, children, className }: { lensIds: LensId[]; children: ReactNode; className?: string }) {
  const { active } = useContext(LensContext);
  const dimmed = active !== null && !lensIds.includes(active);
  return (
    <div className={`${className ?? ""} ${dimmed ? "is-dimmed" : ""}`} data-lens-entry data-dimmed={dimmed || undefined}>
      {children}
    </div>
  );
}

export function LensKey({ counts }: { counts: Record<LensId, number> }) {
  const { active, setActive } = useContext(LensContext);
  const liveId = useId();
  const activeLens = lenses.find((l) => l.id === active);

  function activate(id: LensId | null) {
    setActive(id);
    debug.log("lens", "active", id);
  }

  return (
    <div className="lens-key" onMouseLeave={() => activate(null)}>
      <ul className="lens-key__list">
        {lenses.map((lens) => {
          const pressed = active === lens.id;
          return (
            <li key={lens.id}>
              <button
                type="button"
                className={`lens-key__button ${pressed ? "is-active" : ""}`}
                aria-pressed={pressed}
                data-cursor="ring"
                onMouseEnter={() => activate(lens.id)}
                onFocus={() => activate(lens.id)}
                onBlur={() => activate(null)}
                onClick={() => activate(pressed ? null : lens.id)}
              >
                <span className="lens-key__numeral" aria-hidden="true">{lens.numeral}</span>
                <span className="lens-key__name">{lens.name}</span>
                <span className="lens-key__question">{lens.question}</span>
                <span className="lens-key__count">{counts[lens.id]} {counts[lens.id] === 1 ? "project" : "projects"}</span>
              </button>
            </li>
          );
        })}
      </ul>
      <p id={liveId} className="visually-hidden" aria-live="polite">
        {activeLens ? `${activeLens.name} selected. Highlighting ${counts[activeLens.id]} matching projects.` : "No lens selected. All projects shown."}
      </p>
    </div>
  );
}
