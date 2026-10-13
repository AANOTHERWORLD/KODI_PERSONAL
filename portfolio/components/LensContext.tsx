"use client";

import { createContext, useContext, useId, useState, type ReactNode } from "react";
import type { LensId } from "@/content/types";
import { lenses } from "@/content/lenses";
import { debug } from "@/lib/debug";

// Shared lens highlighting. The LensKey (Home) or LensFilter (Work) sets an active lens;
// every LensAwareEntry inside the provider dims when it lacks that lens. Entries are never
// reordered or hidden. Without JavaScript the key renders as a static list and nothing dims.

type LensState = { active: LensId | null; setActive: (l: LensId | null) => void };
const LensContext = createContext<LensState>({ active: null, setActive: () => {} });

export function LensProvider({ children }: { children: ReactNode }) {
  const [active, setActive] = useState<LensId | null>(null);
  return <LensContext.Provider value={{ active, setActive }}>{children}</LensContext.Provider>;
}

export function LensAwareEntry({ lensIds, children, className, as: Tag = "div" }: { lensIds: LensId[]; children: ReactNode; className?: string; as?: "div" | "li" | "article" }) {
  const { active } = useContext(LensContext);
  const dimmed = active !== null && !lensIds.includes(active);
  return (
    <Tag className={`${className ?? ""} ${dimmed ? "is-dimmed" : ""}`} data-lens-entry data-dimmed={dimmed || undefined}>
      {children}
    </Tag>
  );
}

export function LensKey({ counts, compact = false }: { counts: Record<LensId, number>; compact?: boolean }) {
  const { active, setActive } = useContext(LensContext);
  const liveId = useId();
  const activeLens = lenses.find((l) => l.id === active);

  function activate(id: LensId | null) {
    setActive(id);
    debug.log("lens", "active", id);
  }

  return (
    <div className={`lens-key ${compact ? "lens-key--compact" : ""}`} onMouseLeave={() => activate(null)}>
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
                <span className="lens-key__dot" aria-hidden="true" />
                <span className="lens-key__name">{lens.name}</span>
                {!compact && <span className="lens-key__question">{lens.question}</span>}
                <span className="lens-key__count tag">{counts[lens.id]} {counts[lens.id] === 1 ? "project" : "projects"}</span>
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
