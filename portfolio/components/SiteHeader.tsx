"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { usePathname } from "next/navigation";
import { portfolio } from "@/content/portfolio";

// Fixed header with the wordmark and a full-screen menu overlay. The overlay traps focus,
// closes on Escape and on link click, and toggles its label to Close. The header switches
// ink color while it crosses a [data-header-invert] section (the accent band).
//
// Z-index map: header 50, menu overlay 60 (see globals.css).

const NAV = [
  { href: "/work/", label: "Work" },
  { href: "/approach/", label: "Approach" },
  { href: "/about/", label: "About" },
  { href: "/contact/", label: "Contact" },
];

export default function SiteHeader() {
  const [open, setOpen] = useState(false);
  const [inverted, setInverted] = useState(false);
  const overlayRef = useRef<HTMLDivElement | null>(null);
  const toggleRef = useRef<HTMLButtonElement | null>(null);
  const pathname = usePathname();

  useEffect(() => {
    setOpen(false);
  }, [pathname]);

  useEffect(() => {
    document.documentElement.classList.toggle("menu-open", open);
    if (!open) return;
    const overlay = overlayRef.current;
    const focusables = () =>
      Array.from(overlay?.querySelectorAll<HTMLElement>("a[href], button:not([disabled])") ?? []);
    focusables()[0]?.focus();
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
    return () => document.removeEventListener("keydown", onKey);
  }, [open]);

  useEffect(() => {
    const bands = Array.from(document.querySelectorAll<HTMLElement>("[data-header-invert]"));
    if (!bands.length) {
      setInverted(false);
      return;
    }
    const headerHeight = 72;
    const observer = new IntersectionObserver(
      (entries) => {
        const crossing = entries.some((e) => e.isIntersecting);
        setInverted(crossing);
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
          <Link href="/" className="wordmark" aria-label={`${portfolio.wordmark}, home`} data-cursor="ring">
            {portfolio.wordmark}
          </Link>
          <button
            ref={toggleRef}
            type="button"
            className="menu-toggle"
            aria-expanded={open}
            aria-controls="site-menu"
            onClick={() => setOpen((v) => !v)}
            data-cursor="ring"
          >
            <span className="menu-toggle__label">{open ? "Close" : "Menu"}</span>
            <span className="menu-toggle__icon" aria-hidden="true"><i /><i /></span>
          </button>
        </div>
      </header>
      <div id="site-menu" ref={overlayRef} className="menu-overlay" role="dialog" aria-modal="true" aria-label="Site menu" hidden={!open}>
        <nav className="menu-overlay__nav" aria-label="Primary">
          <ol>
            {NAV.map((item, i) => (
              <li key={item.href}>
                <Link href={item.href} onClick={() => setOpen(false)} data-cursor="ring">
                  <span className="menu-overlay__num">{String(i + 1).padStart(2, "0")}</span>
                  <span className="menu-overlay__label">{item.label}</span>
                </Link>
              </li>
            ))}
          </ol>
        </nav>
        <ul className="menu-overlay__links">
          <li><a href={`mailto:${portfolio.email}?subject=${encodeURIComponent(portfolio.emailSubject)}`} data-cursor="ring">{portfolio.email}</a></li>
          <li><a href={portfolio.linkedin} rel="me noopener" data-cursor="ring">LinkedIn</a></li>
          <li><a href={portfolio.instagram} rel="me noopener" data-cursor="ring">Instagram</a></li>
        </ul>
      </div>
    </>
  );
}
