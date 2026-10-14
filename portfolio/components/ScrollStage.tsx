"use client";

import { useEffect, useRef, type ReactNode } from "react";
import { debug } from "@/lib/debug";

// The landing stage, ported from the reference prototype's custom code.
//
// Structure: .stage (one viewport, overflow hidden) > .stage__canvas (300vw x 300vh, centered)
// > statement (centered in the canvas) + tiles (absolute). The canvas pans against the mouse
// (strength 0.55 of the viewport, eased 0.10 per frame), so the statement and the tiles move
// together. Tiles are sized from data-size (1 to 5, lerp 240 to 520px with small jitter) and
// placed on a golden-ish spiral around a safe zone padded 120px around the statement, never
// overlapping each other (120px gap) and never leaving the canvas (140px edge padding). The
// random source is seeded, so the field is the same on every visit at a given viewport.
//
// Enhanced only on wide viewports; everywhere else the CSS grid fallback renders. Under
// reduced motion the field is laid out once and does not pan.
//
// Z-index map inside the stage: tiles 1, statement 2 (see globals.css).

const SIZE_MIN = 1;
const SIZE_MAX = 5;
const MIN_TILE_W = 240;
const MAX_TILE_W = 520;
const SIZE_JITTER = 0.08;
const SAFE_ZONE_PADDING = 120;
const MIN_GAP = 120;
const SPIRAL_TURN = 0.62;
const RADIAL_STEP = 150;
const JITTER = 70;
const MAX_TRIES_PER_TILE = 900;
const SEED = 1337;
const EDGE_PADDING_BASE = 140;
const RADIUS_PADDING = 80;
const MOUSE_STRENGTH = 0.55;
const EASE = 0.1;

type Rect = { x: number; y: number; w: number; h: number };

function mulberry32(a: number) {
  return function () {
    let t = (a += 0x6d2b79f5);
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const clamp = (v: number, min: number, max: number) => Math.max(min, Math.min(max, v));
const lerp = (a: number, b: number, t: number) => a + (b - a) * t;
const overlaps = (a: Rect, b: Rect) => !(a.x + a.w <= b.x || a.x >= b.x + b.w || a.y + a.h <= b.y || a.y >= b.y + b.h);
const inflate = (r: Rect, pad: number): Rect => ({ x: r.x - pad, y: r.y - pad, w: r.w + pad * 2, h: r.h + pad * 2 });

function layout(canvas: HTMLElement, headline: HTMLElement | null, tiles: HTMLElement[]) {
  const rand = mulberry32(SEED);
  // Reset sizes so the base CSS size (and its aspect ratio) can be read again.
  tiles.forEach((el) => {
    el.style.width = "";
    el.style.height = "";
  });
  void canvas.offsetHeight;
  tiles.forEach((el) => {
    const r = el.getBoundingClientRect();
    const aspect = Math.max(1, r.width) / Math.max(1, r.height);
    const raw = parseFloat(el.dataset.size || "");
    let t = Number.isFinite(raw) ? (clamp(raw, SIZE_MIN, SIZE_MAX) - SIZE_MIN) / (SIZE_MAX - SIZE_MIN) : rand();
    t = clamp(t + (rand() - 0.5) * 2 * SIZE_JITTER, 0, 1);
    const w = lerp(MIN_TILE_W, MAX_TILE_W, t);
    el.style.width = `${Math.round(w)}px`;
    el.style.height = `${Math.round(w / aspect)}px`;
  });
  void canvas.offsetHeight;

  const stageRect = canvas.getBoundingClientRect();
  const stageW = stageRect.width;
  const stageH = stageRect.height;
  if (stageW < 100 || stageH < 100) return false;

  let safe: Rect;
  if (headline) {
    const hr = headline.getBoundingClientRect();
    safe = { x: hr.left - stageRect.left, y: hr.top - stageRect.top, w: hr.width, h: hr.height };
  } else {
    safe = { x: stageW / 2 - 250, y: stageH / 2 - 250, w: 500, h: 500 };
  }
  safe = inflate(safe, SAFE_ZONE_PADDING);

  const placed: Rect[] = [];
  const meta = tiles
    .map((el) => {
      const r = el.getBoundingClientRect();
      return { el, w: Math.max(1, r.width), h: Math.max(1, r.height) };
    })
    .sort((a, b) => b.w * b.h - a.w * a.h);
  const maxR = Math.max(0, Math.min(stageW, stageH) / 2 - EDGE_PADDING_BASE - RADIUS_PADDING);

  const spiral = (i: number) => {
    const angle = i * (Math.PI * 2 * SPIRAL_TURN);
    const radius = Math.min(RADIAL_STEP * Math.sqrt(i + 1), maxR);
    return { x: Math.cos(angle) * radius + (rand() - 0.5) * 2 * JITTER, y: Math.sin(angle) * radius + (rand() - 0.5) * 2 * JITTER };
  };

  meta.forEach(({ el, w, h }, idx) => {
    const padX = Math.min(EDGE_PADDING_BASE, Math.max(0, (stageW - w) / 2 - 12));
    const padY = Math.min(EDGE_PADDING_BASE, Math.max(0, (stageH - h) / 2 - 12));
    const toRect = (p: { x: number; y: number }): Rect => ({
      x: clamp(stageW / 2 + p.x - w / 2, padX, stageW - padX - w),
      y: clamp(stageH / 2 + p.y - h / 2, padY, stageH - padY - h),
      w,
      h,
    });
    let chosen: Rect | null = null;
    for (let t = 0; t < MAX_TRIES_PER_TILE; t++) {
      const candidate = toRect(spiral(idx + t * 0.06));
      if (overlaps(candidate, safe)) continue;
      const padded = inflate(candidate, MIN_GAP);
      if (placed.some((r) => overlaps(padded, r))) continue;
      chosen = candidate;
      break;
    }
    if (!chosen) chosen = toRect(spiral(idx));
    el.style.position = "absolute";
    el.style.left = `${chosen.x}px`;
    el.style.top = `${chosen.y}px`;
    placed.push(inflate(chosen, MIN_GAP));
  });
  return true;
}

export default function ScrollStage({ children }: { children: ReactNode }) {
  const ref = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const wide = window.matchMedia("(min-width: 720px)").matches;
    if (!wide) {
      debug.log("stage", "static field", { reduced, wide });
      return;
    }
    const canvas = el.querySelector<HTMLElement>("[data-stage-canvas]");
    const headline = el.querySelector<HTMLElement>("[data-statement]");
    const tiles = Array.from(el.querySelectorAll<HTMLElement>("[data-tile]"));
    if (!canvas || !tiles.length) return;

    el.classList.add("is-enhanced", "is-loading");
    let disposed = false;
    let raf = 0;
    let resizeTimer = 0;

    const run = () => layout(canvas, headline, tiles);

    // Mouse pan: the whole canvas drifts against the pointer.
    let targetX = 0;
    let targetY = 0;
    let currentX = 0;
    let currentY = 0;
    const onMove = (e: MouseEvent) => {
      const nx = (e.clientX / window.innerWidth - 0.5) * 2;
      const ny = (e.clientY / window.innerHeight - 0.5) * 2;
      targetX = -nx * window.innerWidth * MOUSE_STRENGTH;
      targetY = -ny * window.innerHeight * MOUSE_STRENGTH;
    };
    const tick = () => {
      currentX += (targetX - currentX) * EASE;
      currentY += (targetY - currentY) * EASE;
      canvas.style.transform = `translate(-50%, -50%) translate3d(${currentX}px, ${currentY}px, 0)`;
      raf = window.requestAnimationFrame(tick);
    };
    function pan() {
      window.addEventListener("mousemove", onMove, { passive: true });
      raf = window.requestAnimationFrame(tick);
    }


    const imgs = Array.from(canvas.querySelectorAll("img")).filter((img) => !img.complete);
    let pending = imgs.length;
    let started = false;
    const start = () => {
      if (started || disposed) return;
      started = true;
      run();
      window.setTimeout(() => !disposed && run(), 180);
      el.classList.remove("is-loading");
      el.classList.add("is-ready");
      debug.log("stage", "laid out", { tiles: tiles.length, reduced });
      if (!reduced) pan();
    };
    const done = () => {
      if (--pending <= 0) start();
    };
    if (!pending) start();
    else {
      imgs.forEach((img) => {
        img.addEventListener("load", done, { once: true });
        img.addEventListener("error", done, { once: true });
      });
      window.setTimeout(start, 1400);
    }

    const onResize = () => {
      window.clearTimeout(resizeTimer);
      resizeTimer = window.setTimeout(() => started && run(), 150);
    };
    window.addEventListener("resize", onResize);

    return () => {
      disposed = true;
      window.cancelAnimationFrame(raf);
      window.clearTimeout(resizeTimer);
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("resize", onResize);
      canvas.style.transform = "";
      tiles.forEach((t) => t.removeAttribute("style"));
      el.classList.remove("is-enhanced", "is-loading", "is-ready");
    };
  }, []);

  return (
    <div ref={ref} className="stage" data-scroll-stage="true">
      <div className="stage__canvas" data-stage-canvas>
        {children}
      </div>
    </div>
  );
}
