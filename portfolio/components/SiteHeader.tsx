"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { usePathname } from "next/navigation";
import { portfolio } from "@/content/portfolio";

// Fixed header with the wordmark and a full-screen menu, choreographed like the reference:
//   open   0ms   overlay displays
//          400ms the dark circle grows from the center (0 to 500vw, 800ms, out-cubic); the two
//                lines scale away and the X scales in (600ms, in-out-back); "Menu" rolls up to
//                reveal "Close" (400ms)
//          800ms+200ms per link: the number fades to 60% (300ms ease-in) and the label slides up
//                from 20% with a 30deg skew (400ms, out-cubic)
//   close  0ms   links and numbers fade out (200ms)
//          400ms the circle shrinks (500ms), icon and label roll back (300ms); then the overlay
//                is hidden
// The overlay traps focus, closes on Escape and on link click. The header switches ink color
// while it crosses a [data-header-invert] section (the accent band, the footer).
//
// Z-index map: header 50 (70 while open), menu overlay 60 (see globals.css).

const NAV = [
  { href: "/work/", label: "Work" },
  { href: "/approach/", label: "Approach" },
  { href: "/about/", label: "About" },
  { href: "/contact/", label: "Contact" },
];

const CLOSE_MS = 900;

export default function SiteHeader() {
  const [open, setOpen] = useState(false);
  const [shown, setShown] = useState(false);
  const [inverted, setInverted] = useState(false);
  const overlayRef = useRef<HTMLDivElement | null>(null);
  const toggleRef = useRef<HTMLButtonElement | null>(null);
  const pathname = usePathname();

  useEffect(() => {
    setOpen(false);
  }, [pathname]);

  // Keep the overlay displayed until the closing choreography finishes.
  useEffect(() => {
    if (open) {
      setShown(true);
      return;
    }
    const t = window.setTimeout(() => setShown(false), CLOSE_MS);
    return () => window.clearTimeout(t);
  }, [open]);

  useEffect(() => {
    document.documentElement.classList.toggle("menu-open", open);
    if (!open) return;
    const overlay = overlayRef.current;
    const focusables = () => Array.from(overlay?.querySelectorAll<HTMLElement>("a[href], button:not([disabled])") ?? []);
    const focusTimer = window.setTimeout(() => focusables()[0]?.focus({ preventScroll: true }), 900);
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") {
        setOpen(false);
        toggleRef.current?.focus();
        return;
      }
      if (event.key === "Tab") {
        const items = [toggleRef.current, ...focusables()].filter(Boolean) as HTMLElement[];
        if (!items.length) return;
        const first = items[0];
        const last = items[items.length - 1];
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first.focus();
        }
      }
    }
    document.addEventListener("keydown", onKey);
    return () => {
      window.clearTimeout(focusTimer);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  useEffect(() => {
    const bands = Array.from(document.querySelectorAll<HTMLElement>("[data-header-invert]"));
    document.documentElement.style.setProperty("--header-bg", "var(--bg)");
    if (!bands.length) {
      setInverted(false);
      return;
    }
    const headerHeight = 72;
    const observer = new IntersectionObserver(
      (entries) => {
        const crossing = entries.find((e) => e.isIntersecting);
        setInverted(!!crossing);
        // Tint the header's backing band with the color of the section beneath it.
        const cs = crossing ? getComputedStyle(crossing.target) : null;
        const band = cs?.getPropertyValue("--header-band").trim();
        const bg = cs?.backgroundColor;
        document.documentElement.style.setProperty("--header-bg", band || (bg && bg !== "rgba(0, 0, 0, 0)" ? bg : "var(--bg)"));
      },
      { rootMargin: `-${headerHeight}px 0px -${Math.max(window.innerHeight - headerHeight, 1)}px 0px`, threshold: 0 },
    );
    bands.forEach((b) => observer.observe(b));
    return () => observer.disconnect();
  }, [pathname]);

  return (
    <>
      <header className={`site-header ${inverted ? "is-inverted" : ""} ${open ? "is-open" : ""}`}>
        <a className="skip-link" href="#main">Skip to content</a>
        <div className="site-header__inner">
          <Link href="/" className="wordmark" aria-label={`${portfolio.wordmark}, home`}>
            {portfolio.wordmark}
          </Link>
          <button ref={toggleRef} type="button" className="menu-toggle" aria-expanded={open} aria-controls="site-menu" onClick={() => setOpen((v) => !v)}>
            <span className="menu-toggle__text" aria-hidden="true">
              <span className="menu-toggle__roll">
                <span>Menu</span>
                <span>Close</span>
              </span>
            </span>
            <span className="visually-hidden">{open ? "Close menu" : "Open menu"}</span>
            <span className="menu-toggle__icon" aria-hidden="true">
              <span className="menu-toggle__lines"><i /><i /></span>
              <span className="menu-toggle__x"><i /><i /></span>
            </span>
          </button>
        </div>
      </header>
      <div
        id="site-menu"
        ref={overlayRef}
        className={`menu ${open ? "is-open" : ""} ${shown ? "is-shown" : ""}`}
        role="dialog"
        aria-modal="true"
        aria-label="Site menu"
        inert={!open}
      >
        <div className="menu__circle" aria-hidden="true" />
        <nav className="menu__nav" aria-label="Primary">
          <ol>
            {NAV.map((item, i) => (
              <li key={item.href} style={{ "--i": i } as React.CSSProperties}>
                <Link href={item.href} className="menu__link" onClick={() => setOpen(false)} data-sweep>
                  <span className="menu__num">{String(i + 1).padStart(2, "0")}.</span>
                  <span className="menu__overflow">
                    <span className="menu__label">{item.label}</span>
                    <span className="menu__line" aria-hidden="true" />
                  </span>
                </Link>
              </li>
            ))}
          </ol>
          <ul className="menu__links">
            <li><a href={`mailto:${portfolio.email}?subject=${encodeURIComponent(portfolio.emailSubject)}`} data-sweep className="sweep-link">{portfolio.email}</a></li>
            {portfolio.linkedin && <li><a href={portfolio.linkedin} rel="me noopener" data-sweep className="sweep-link">LinkedIn</a></li>}
            {portfolio.instagram && <li><a href={portfolio.instagram} rel="me noopener" data-sweep className="sweep-link">Instagram</a></li>}
          </ul>
        </nav>
      </div>
    </>
  );
}
