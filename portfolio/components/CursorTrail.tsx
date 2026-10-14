"use client";

import { useEffect, useRef } from "react";
import { debug } from "@/lib/debug";

// Signature interaction, ported from the reference prototype: a dot that follows the pointer
// with spring physics (stretching along its velocity), and a canvas tail of stamped circles
// whose length and radius grow with speed and fade with age. Three modes: default dot,
// "link" (precision ring over links and buttons), "tile" (presence ring over project tiles).
//
// Z-index map (also documented in globals.css):
//   trail canvas       9000  (pointer-events: none, above content, below cursor)
//   cursor element     9001  (pointer-events: none)
//
// Disabled on coarse pointers (touch) and under prefers-reduced-motion, where the native
// cursor stays (html.has-custom-cursor is only set when enabled).

const LINK_SELECTOR = "a, button, [role='button'], input, select, textarea, summary, [tabindex]:not([tabindex='-1'])";
const TILE_SELECTOR = ".cursor-tile";

const FOLLOW = 0.18;
const DAMPING = 0.75;
const BASE_TTL = 260;
const SPEED_TTL = 7.0;
const MAX_TTL = 900;
const MAX_POINTS = 140;
const BASE_RADIUS = 1.6;
const SPEED_RADIUS = 0.1;
const MAX_RADIUS = 9;
const TAIL_ALPHA = 0.22;
const MAX_SPEED = 60;
const STAMP_SPACING = 2.2;

type Point = { x: number; y: number; t: number; ttl: number; r: number; alpha: number };

export default function CursorTrail() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const dotRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const coarse = window.matchMedia("(pointer: coarse)").matches || !window.matchMedia("(hover: hover)").matches;
    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (coarse || reducedMotion) {
      debug.log("cursor", "disabled", { coarse, reducedMotion });
      return;
    }
    const canvas = canvasRef.current;
    const dot = dotRef.current;
    if (!canvas || !dot) return;
    const ctx = canvas.getContext("2d", { alpha: true });
    if (!ctx) return;

    document.documentElement.classList.add("has-custom-cursor");
    debug.log("cursor", "enabled");

    const trailColor = getComputedStyle(document.documentElement).getPropertyValue("--trail-color").trim() || "#000";
    let dpr = Math.max(1, window.devicePixelRatio || 1);
    let cw = window.innerWidth;
    let ch = window.innerHeight;
    let mouseX = cw / 2;
    let mouseY = ch / 2;
    let x = mouseX;
    let y = mouseY;
    let vx = 0;
    let vy = 0;
    let mode: "default" | "link" | "tile" = "default";
    let isDown = false;
    let seen = false;
    let raf = 0;
    const points: Point[] = [];

    function resize() {
      dpr = Math.max(1, window.devicePixelRatio || 1);
      cw = window.innerWidth;
      ch = window.innerHeight;
      canvas!.width = Math.floor(cw * dpr);
      canvas!.height = Math.floor(ch * dpr);
      canvas!.style.width = `${cw}px`;
      canvas!.style.height = `${ch}px`;
      ctx!.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx!.clearRect(0, 0, cw, ch);
    }

    function setMode(next: typeof mode) {
      if (mode === next) return;
      mode = next;
      dot!.classList.toggle("is-link", mode === "link");
      dot!.classList.toggle("is-tile", mode === "tile");
    }

    const onMove = (e: MouseEvent) => {
      mouseX = e.clientX;
      mouseY = e.clientY;
      if (!seen) {
        seen = true;
        x = mouseX;
        y = mouseY;
        dot!.classList.add("is-visible");
      }
    };
    const onDown = () => {
      isDown = true;
      dot!.classList.add("is-down");
    };
    const onUp = () => {
      isDown = false;
      dot!.classList.remove("is-down");
    };
    const onOver = (e: Event) => {
      const target = e.target as Element | null;
      if (target?.closest?.(TILE_SELECTOR)) return setMode("tile");
      if (target?.closest?.(LINK_SELECTOR)) return setMode("link");
      setMode("default");
    };
    const onOut = () => setMode("default");
    const onLeave = () => {
      seen = false;
      dot!.classList.remove("is-visible");
    };

    const lerp = (a: number, b: number, t: number) => a + (b - a) * t;

    function addPoint(px: number, py: number, speed: number) {
      const s = Math.min(speed, MAX_SPEED);
      points.push({ x: px, y: py, t: performance.now(), ttl: Math.min(BASE_TTL + s * SPEED_TTL, MAX_TTL), r: Math.min(BASE_RADIUS + s * SPEED_RADIUS, MAX_RADIUS), alpha: 1 });
      if (points.length > MAX_POINTS) points.shift();
    }

    function stampBetween(p1: Point, p2: Point) {
      const dx = p2.x - p1.x;
      const dy = p2.y - p1.y;
      const steps = Math.max(1, Math.floor(Math.hypot(dx, dy) / STAMP_SPACING));
      for (let i = 1; i <= steps; i++) {
        const t = i / steps;
        ctx!.globalAlpha = lerp(p1.alpha, p2.alpha, t) * TAIL_ALPHA;
        ctx!.beginPath();
        ctx!.arc(p1.x + dx * t, p1.y + dy * t, lerp(p1.r, p2.r, t), 0, Math.PI * 2);
        ctx!.fill();
      }
    }

    function frame() {
      const dx = mouseX - x;
      const dy = mouseY - y;
      vx = vx * DAMPING + dx * FOLLOW;
      vy = vy * DAMPING + dy * FOLLOW;
      x += vx;
      y += vy;
      const speed = Math.min(Math.hypot(vx, vy), MAX_SPEED);
      if (seen) addPoint(x, y, speed);

      // Hard clear every frame, then redraw the tail with per-point decay.
      ctx!.clearRect(0, 0, cw, ch);
      const now = performance.now();
      ctx!.fillStyle = trailColor;
      ctx!.globalCompositeOperation = "source-over";
      for (let i = points.length - 1; i >= 0; i--) {
        const age = now - points[i].t;
        if (age >= points[i].ttl) {
          points.splice(i, 1);
          continue;
        }
        const k = 1 - age / points[i].ttl;
        points[i].alpha = k * k;
      }
      for (let i = 1; i < points.length; i++) stampBetween(points[i - 1], points[i]);
      ctx!.globalAlpha = 1;

      // The dot stretches along its velocity in the default mode only.
      const stretch = Math.min(speed / 40, 1) * 0.35;
      let scaleX = 1;
      let scaleY = 1;
      let rotate = 0;
      if (mode === "default") {
        scaleX = 1 + stretch;
        scaleY = 1 - stretch * 0.6;
        rotate = Math.atan2(vy, vx);
      }
      dot!.style.transform = `translate(${x}px, ${y}px) translate(-50%, -50%) rotate(${rotate}rad) scale(${scaleX}, ${scaleY})${isDown ? " scale(0.85)" : ""}`;
      raf = window.requestAnimationFrame(frame);
    }

    resize();
    window.addEventListener("resize", resize);
    window.addEventListener("mousemove", onMove, { passive: true });
    window.addEventListener("mousedown", onDown);
    window.addEventListener("mouseup", onUp);
    document.addEventListener("pointerover", onOver);
    document.addEventListener("pointerout", onOut);
    document.documentElement.addEventListener("mouseleave", onLeave);
    raf = window.requestAnimationFrame(frame);

    return () => {
      window.cancelAnimationFrame(raf);
      window.removeEventListener("resize", resize);
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mousedown", onDown);
      window.removeEventListener("mouseup", onUp);
      document.removeEventListener("pointerover", onOver);
      document.removeEventListener("pointerout", onOut);
      document.documentElement.removeEventListener("mouseleave", onLeave);
      document.documentElement.classList.remove("has-custom-cursor");
    };
  }, []);

  return (
    <>
      <canvas ref={canvasRef} className="cursor-trail" aria-hidden="true" />
      <div ref={dotRef} className="cursor-dot" aria-hidden="true" />
    </>
  );
}
