"use client";

import { useEffect, useRef, type ReactNode } from "react";

// Full-bleed portrait with a subtle scale-in on scroll (CSS transition toggled by an
// IntersectionObserver). Static under reduced motion.
export default function Portrait({ children }: { children: ReactNode }) {
  const ref = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    const el = ref.current;
    if (!el || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const io = new IntersectionObserver((entries) => entries.forEach((e) => el.classList.toggle("is-in", e.isIntersecting)), { threshold: 0.2 });
    io.observe(el);
    return () => io.disconnect();
  }, []);
  return (
    <div ref={ref} className="portrait">
      {children}
    </div>
  );
}
