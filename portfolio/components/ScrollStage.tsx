"use client";

import { useEffect, useRef, type ReactNode } from "react";
import { getGsap } from "@/lib/gsap";
import { debug } from "@/lib/debug";

// The landing scroll stage. The statement is fixed in the viewport while tiles drift upward at
// speeds set by their depth, scrubbed by GSAP ScrollTrigger on transforms only. The stage is
// enhanced only on wide viewports without reduced motion: everywhere else the CSS grid
// fallback renders (statement at top, staggered two-column tiles, no parallax).
//
// Z-index map inside the stage: tiles 1, statement 2 (see globals.css).

export default function ScrollStage({ children, heightVh }: { children: ReactNode; heightVh: number }) {
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
        const travel = -(60 + depth * 60); // px of extra upward drift across the stage, by depth
        gsap.fromTo(tile, { y: 0 }, { y: travel, ease: "none", scrollTrigger: { trigger: el, start: "top top", end: "bottom bottom", scrub: 0.6 } });
      });
      const statement = el.querySelector<HTMLElement>("[data-statement]");
      if (statement) {
        ScrollTrigger.create({ trigger: el, start: "top top", end: "bottom bottom", pin: statement, pinSpacing: false });
      }
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
    <div ref={ref} className="stage" data-scroll-stage="true" style={{ "--stage-height": heightVh } as React.CSSProperties}>
      {children}
    </div>
  );
}
