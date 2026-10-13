"use client";

import { useEffect, useRef, type ReactNode } from "react";
import { getGsap } from "@/lib/gsap";
import { debug } from "@/lib/debug";

// The landing stage: one viewport tall. The statement sits at the center and a handful of tiles
// are scattered around it, drifting upward at speeds set by depth as the stage scrolls away
// (GSAP ScrollTrigger, transforms only). Enhanced only on wide viewports without reduced
// motion: everywhere else the CSS grid fallback renders (statement at top, two-column tiles).
//
// Z-index map inside the stage: tiles 1, statement 2 (see globals.css).

export default function ScrollStage({ children }: { children: ReactNode }) {
  const ref = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const wide = window.matchMedia("(min-width: 720px)").matches;
    if (reduced || !wide) {
      debug.log("stage", "static field", { reduced, wide });
      return;
    }
    el.classList.add("is-enhanced");
    const { gsap, ScrollTrigger } = getGsap();
    const ctx = gsap.context(() => {
      const tiles = Array.from(el.querySelectorAll<HTMLElement>("[data-tile]"));
      tiles.forEach((tile) => {
        const depth = Number(tile.dataset.depth || 2);
        const travel = -(80 + depth * 90); // px of upward drift by depth while the stage scrolls away
        gsap.fromTo(tile, { y: 0 }, { y: travel, ease: "none", scrollTrigger: { trigger: el, start: "top top", end: "bottom top", scrub: 0.6 } });
      });
    }, el);
    debug.log("stage", "enhanced", { tiles: el.querySelectorAll("[data-tile]").length });
    const onResize = () => ScrollTrigger.refresh();
    window.addEventListener("resize", onResize);
    return () => {
      window.removeEventListener("resize", onResize);
      ctx.revert();
      el.classList.remove("is-enhanced");
    };
  }, []);

  return (
    <div ref={ref} className="stage" data-scroll-stage="true">
      {children}
    </div>
  );
}
