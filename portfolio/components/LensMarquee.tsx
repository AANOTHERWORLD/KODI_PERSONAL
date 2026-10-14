"use client";

import { useEffect, useRef } from "react";
import { getGsap } from "@/lib/gsap";
import { lenses } from "@/content/lenses";

// Two rows of the four lenses at display size, separated by faint dots. As the section
// crosses the viewport (scroll scrub), the top row slides from -50% to 0 and the bottom row
// from 0 to -50%, while the block scales 1 to 1.3 and rotates -3deg to 5deg. Decorative:
// aria-hidden, with a visually hidden list for screen readers.
export default function LensMarquee() {
  const ref = useRef<HTMLDivElement | null>(null);
  const top = [...lenses, ...lenses];
  const bottom = [...lenses.slice().reverse(), ...lenses.slice().reverse()];

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const { gsap } = getGsap();
    const effect = el.querySelector<HTMLElement>("[data-effect]");
    const rows = Array.from(el.querySelectorAll<HTMLElement>("[data-row]"));
    if (!effect || rows.length < 2) return;
    const ctx = gsap.context(() => {
      const tl = gsap.timeline({ scrollTrigger: { trigger: el, start: "top bottom", end: "bottom top", scrub: true } });
      tl.fromTo(rows[0], { xPercent: -50 }, { xPercent: 0, ease: "none" }, 0);
      tl.fromTo(rows[1], { xPercent: 0 }, { xPercent: -50, ease: "none" }, 0);
      tl.fromTo(effect, { scale: 1, rotate: -3 }, { scale: 1.3, rotate: 5, ease: "none" }, 0);
    }, el);
    return () => ctx.revert();
  }, []);

  return (
    <div ref={ref} className="marquee">
      <h2 className="visually-hidden">The four lenses</h2>
      <ul className="visually-hidden">
        {lenses.map((l) => <li key={l.id}>{l.name}</li>)}
      </ul>
      <div className="marquee__effect" data-effect aria-hidden="true">
        {[top, bottom].map((row, i) => (
          <div key={i} className="marquee__row" data-row>
            {row.map((l, j) => (
              <span key={`${l.id}-${j}`} className="marquee__item">
                <span className="marquee__text">{l.name}</span>
                <span className="marquee__dot" />
              </span>
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}
