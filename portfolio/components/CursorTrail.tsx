"use client";

import { useEffect, useRef } from "react";
import { debug } from "@/lib/debug";

// Signature interaction: a custom dot-to-ring cursor and a momentum-scaled canvas trail.
//
// Z-index map (also documented in globals.css):
//   content            auto
//   site header        50
//   menu overlay       60
//   trail canvas       9000  (pointer-events: none, above content, below cursor)
//   cursor element     9001  (pointer-events: none)
//
// Disabled entirely on coarse pointers (touch) and under prefers-reduced-motion, where the
// native cursor is restored by CSS (html.has-fine-pointer is only set when enabled).

const TRAIL_TTL_MS = 380;
const INTERACTIVE_SELECTOR = "a, button, [role='button'], input, select, textarea, summary, [data-cursor='ring']";

type Point = { x: number; y: number; t: number };

export default function CursorTrail() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const cursorRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const finePointer = window.matchMedia("(hover: hover) and (pointer: fine)").matches && !window.matchMedia("(pointer: coarse)").matches;
    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (!finePointer || reducedMotion) {
      debug.log("cursor", "disabled", { finePointer, reducedMotion });
      return;
    }

    const canvas = canvasRef.current;
    const cursor = cursorRef.current;
    if (!canvas || !cursor) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    document.documentElement.classList.add("has-custom-cursor");
    debug.log("cursor", "enabled");

    const points: Point[] = [];
    let target = { x: -100, y: -100 };
    let eased = { x: -100, y: -100 };
    let ring = false;
    let visible = false;
    let raf = 0;
    let dpr = 1;
    const accent = getComputedStyle(document.documentElement).getPropertyValue("--trail-color").trim() || "rgba(64,64,64,0.55)";

    function resize() {
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas!.width = Math.floor(window.innerWidth * dpr);
      canvas!.height = Math.floor(window.innerHeight * dpr);
      canvas!.style.width = `${window.innerWidth}px`;
      canvas!.style.height = `${window.innerHeight}px`;
      ctx!.setTransform(dpr, 0, 0, dpr, 0, 0);
    }

    function onMove(event: PointerEvent) {
      target = { x: event.clientX, y: event.clientY };
      points.push({ x: event.clientX, y: event.clientY, t: performance.now() });
      if (!visible) {
        visible = true;
        eased = { ...target };
        cursor!.classList.add("is-visible");
      }
    }

    function onOver(event: Event) {
      const el = event.target as Element | null;
      const next = !!el?.closest?.(INTERACTIVE_SELECTOR);
      if (next !== ring) {
        ring = next;
        cursor!.classList.toggle("is-ring", ring);
      }
    }

    function onLeave() {
      visible = false;
      cursor!.classList.remove("is-visible");
    }

    function onDown() {
      cursor!.classList.add("is-down");
    }
    function onUp() {
      cursor!.classList.remove("is-down");
    }

    function frame() {
      const now = performance.now();
      // Prune points older than the TTL so the trail disappears when the pointer stops.
      while (points.length && now - points[0].t > TRAIL_TTL_MS) points.shift();

      // Clear and redraw every frame. No compositing fade or alpha accumulation.
      ctx!.clearRect(0, 0, window.innerWidth, window.innerHeight);

      if (points.length > 1) {
        // Momentum from recent point spacing over time (px per ms).
        const tail = points.slice(-6);
        let dist = 0;
        for (let i = 1; i < tail.length; i++) {
          dist += Math.hypot(tail[i].x - tail[i - 1].x, tail[i].y - tail[i - 1].y);
        }
        const span = Math.max(tail[tail.length - 1].t - tail[0].t, 1);
        const momentum = Math.min(dist / span, 3); // 0 (still) to 3 (fast)
        const baseWidth = 1.5 + momentum * 5; // 1.5px slow, up to 16.5px fast

        ctx!.lineCap = "round";
        ctx!.lineJoin = "round";
        for (let i = 1; i < points.length; i++) {
          const age = (now - points[i].t) / TRAIL_TTL_MS; // 0 new, 1 old
          const life = 1 - age;
          ctx!.strokeStyle = accent;
          ctx!.globalAlpha = Math.max(life, 0) * 0.9;
          ctx!.lineWidth = Math.max(baseWidth * life, 0.5);
          ctx!.beginPath();
          ctx!.moveTo(points[i - 1].x, points[i - 1].y);
          ctx!.lineTo(points[i].x, points[i].y);
          ctx!.stroke();
        }
        ctx!.globalAlpha = 1;
      }

      // Light easing so the cursor trails the true pointer slightly.
      eased.x += (target.x - eased.x) * 0.35;
      eased.y += (target.y - eased.y) * 0.35;
      cursor!.style.transform = `translate3d(${eased.x}px, ${eased.y}px, 0) translate(-50%, -50%)`;

      raf = window.requestAnimationFrame(frame);
    }

    resize();
    window.addEventListener("resize", resize);
    window.addEventListener("pointermove", onMove, { passive: true });
    window.addEventListener("pointerover", onOver, { passive: true });
    window.addEventListener("pointerdown", onDown, { passive: true });
    window.addEventListener("pointerup", onUp, { passive: true });
    document.documentElement.addEventListener("mouseleave", onLeave);
    raf = window.requestAnimationFrame(frame);

    return () => {
      window.cancelAnimationFrame(raf);
      window.removeEventListener("resize", resize);
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerover", onOver);
      window.removeEventListener("pointerdown", onDown);
      window.removeEventListener("pointerup", onUp);
      document.documentElement.removeEventListener("mouseleave", onLeave);
      document.documentElement.classList.remove("has-custom-cursor");
    };
  }, []);

  return (
    <>
      <canvas ref={canvasRef} className="cursor-trail" aria-hidden="true" />
      <div ref={cursorRef} className="cursor" aria-hidden="true">
        <span className="cursor__dot" />
        <span className="cursor__ring" />
      </div>
    </>
  );
}
