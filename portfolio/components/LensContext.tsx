"use client";

import { createContext, useContext, useId, useState, type ReactNode } from "react";
import type { LensId } from "@/content/types";
import { lenses } from "@/content/lenses";
import { debug } from "@/lib/debug";

// Shared lens selection. The LensKey sets an active lens on click (never on hover, so a change
// is always something the visitor did). Entries react in one of two modes:
//   dim     (Home): entries without the lens fade back, nothing moves.
//   filter  (Work): entries without the lens leave the grid and the rest reflow.
// Clicking the active lens again, or "Show all", clears it. Without JavaScript the key renders
// as a static list and every entry shows.

type LensState = { active: LensId | null; setActive: (l: LensId | null) => void };
const LensContext = createContext<LensState>({ active: null, setActive: () => {} });

export function LensProvider({ children }: { children: ReactNode }) {
  const [active, setActive] = useState<LensId | null>(null);
  return <LensContext.Provider value={{ active, setActive }}>{children}</LensContext.Provider>;
}

export function LensAwareEntry({ lensIds, children, className, as: Tag = "div", reveal = false, mode = "dim" }: { lensIds: LensId[]; children: ReactNode; className?: string; as?: "div" | "li" | "article"; reveal?: boolean; mode?: "dim" | "filter" }) {
  const { active } = useContext(LensContext);
  const excluded = active !== null && !lensIds.includes(active);
  const dimmed = excluded && mode === "dim";
  const hidden = excluded && mode === "filter";
  return (
    <Tag key={mode === "filter" ? String(active) : undefined} hidden={hidden || undefined} className={`${className ?? ""} ${dimmed ? "is-dimmed" : ""}`} data-lens-entry data-dimmed={dimmed || undefined} data-reveal={reveal || undefined}>
      {children}
    </Tag>
  );
}

export function LensKey({ counts, compact = false, total, noun = "projects", mode = "filter" }: { counts: Record<LensId, number>; compact?: boolean; total?: number; noun?: string; mode?: "dim" | "filter" }) {
  const verb = mode === "filter" ? "filter" : "highlight";
  const { active, setActive } = useContext(LensContext);
  const liveId = useId();
  const activeLens = lenses.find((l) => l.id === active);

  function toggle(id: LensId) {
    const next = active === id ? null : id;
    setActive(next);
    debug.log("lens", "active", next);
  }

  return (
    <div className={`lens-key ${compact ? "lens-key--compact" : ""}`}>
      <ul className="lens-key__list">
        {lenses.map((lens) => {
          const pressed = active === lens.id;
          return (
            <li key={lens.id}>
              <button
                type="button"
                className={`lens-key__button ${pressed ? "is-active" : ""}`}
                aria-pressed={pressed}
                onClick={() => toggle(lens.id)}
              >
                <span className="lens-key__dot" aria-hidden="true" />
                <span className="lens-key__name">{lens.name}</span>
                {!compact && <span className="lens-key__question">{lens.question}</span>}
                {!compact && (
                  <span className="lens-key__count tag">
                    {counts[lens.id]} {counts[lens.id] === 1 ? "project" : "projects"}
                    {pressed && <span className="lens-key__selected"> · Selected</span>}
                  </span>
                )}
              </button>
            </li>
          );
        })}
      </ul>
      <div className="lens-key__status">
        {activeLens ? (
          <>
            <p className="lens-key__result">
              {mode === "filter" ? "Showing" : "Highlighting"} {counts[activeLens.id]}{total ? ` of ${total}` : ""} {noun} in {activeLens.name}
            </p>
            <button type="button" className="lens-key__clear" onClick={() => setActive(null)}>Show all</button>
          </>
        ) : (
          <p className="lens-key__result lens-key__result--hint">Select a lens to {verb} the projects.</p>
        )}
      </div>
      <p id={liveId} className="visually-hidden" aria-live="polite">
        {activeLens ? `${activeLens.name} selected. ${mode === "filter" ? "Showing" : "Highlighting"} ${counts[activeLens.id]} matching ${noun}.` : `No lens selected. All ${noun} shown.`}
      </p>
    </div>
  );
}
