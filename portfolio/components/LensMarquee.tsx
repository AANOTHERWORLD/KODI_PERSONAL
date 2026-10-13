"use client";

import { useEffect, useRef } from "react";
import { getGsap } from "@/lib/gsap";
import { lenses } from "@/content/lenses";

// Display-size marquee of the four lenses. Scroll position drives the drift (ScrollTrigger
// scrub on translateX). Decorative: aria-hidden, with a visually hidden list for screen readers.
export default function LensMarquee() {
  const ref = useRef<HTMLDivElement | null>(null);
  const text = lenses.map((l) => l.name).join("  ·  ");

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const { gsap } = getGsap();
    const track = el.querySelector<HTMLElement>("[data-track]");
    if (!track) return;
    const ctx = gsap.context(() => {
      gsap.fromTo(track, { xPercent: 0 }, { xPercent: -22, ease: "none", scrollTrigger: { trigger: el, start: "top bottom", end: "bottom top", scrub: 1 } });
    }, el);
    return () => ctx.revert();
  }, []);

  return (
    <div ref={ref} className="marquee">
      <h2 className="visually-hidden">The four lenses</h2>
      <ul className="visually-hidden">
        {lenses.map((l) => <li key={l.id}>{l.name}</li>)}
      </ul>
      <div className="marquee__band" aria-hidden="true">
        <div className="marquee__track" data-track>
          <span>{text}  ·  </span>
          <span>{text}  ·  </span>
        </div>
      </div>
    </div>
  );
}
