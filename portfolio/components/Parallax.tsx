"use client";

import { useEffect } from "react";
import { debug } from "@/lib/debug";

// Light parallax for work cards. Reads [data-parallax] elements and nudges their image a few
// pixels against scroll. Disabled under reduced motion and on touch.
export default function Parallax() {
  useEffect(() => {
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const coarse = window.matchMedia("(pointer: coarse)").matches;
    if (reduced || coarse) {
      debug.log("index", "parallax disabled", { reduced, coarse });
      return;
    }
    const nodes = Array.from(document.querySelectorAll<HTMLElement>("[data-parallax]"));
    if (!nodes.length) return;
    let raf = 0;
    const MAX = 18;
    function update() {
      raf = 0;
      const vh = window.innerHeight;
      for (const node of nodes) {
        const rect = node.getBoundingClientRect();
        if (rect.bottom < 0 || rect.top > vh) continue;
        const progress = (rect.top + rect.height / 2 - vh / 2) / vh;
        const offset = Math.max(-MAX, Math.min(MAX, -progress * MAX * 2));
        node.style.setProperty("--parallax", `${offset.toFixed(1)}px`);
      }
    }
    function onScroll() {
      if (!raf) raf = window.requestAnimationFrame(update);
    }
    update();
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", onScroll);
    return () => {
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("resize", onScroll);
      if (raf) window.cancelAnimationFrame(raf);
    };
  }, []);
  return null;
}
