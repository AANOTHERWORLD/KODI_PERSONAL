"use client";

import { useEffect, useRef, type ReactNode } from "react";
import { getGsap } from "@/lib/gsap";

// Full-bleed portrait, one viewport tall. As the section scrolls out (its bottom edge travels
// from the viewport bottom to the top) the image slides down 40vh, so it leaves slower than
// the page: the reference's "Project Image Animation". A gradient at the foot blends into
// the accent band that follows. Static under reduced motion.
export default function Portrait({ children }: { children: ReactNode }) {
  const ref = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    const el = ref.current;
    if (!el || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const { gsap } = getGsap();
    const card = el.querySelector<HTMLElement>("[data-card]");
    if (!card) return;
    const ctx = gsap.context(() => {
      gsap.fromTo(card, { y: 0 }, { y: () => window.innerHeight * 0.4, ease: "none", scrollTrigger: { trigger: el, start: "bottom bottom", end: "bottom top", scrub: true, invalidateOnRefresh: true } });
    }, el);
    return () => ctx.revert();
  }, []);
  return (
    <div ref={ref} className="portrait">
      <div className="portrait__card" data-card>
        {children}
      </div>
      <div className="portrait__fade" aria-hidden="true" />
    </div>
  );
}
