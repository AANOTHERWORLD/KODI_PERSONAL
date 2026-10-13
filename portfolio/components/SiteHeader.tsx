import Link from "next/link";
import { portfolio } from "@/lib/content";

const NAV = [
  { href: "/work/", label: "Work" },
  { href: "/approach/", label: "Approach" },
  { href: "/about/", label: "About" },
  { href: "/contact/", label: "Contact" },
];

export default function SiteHeader() {
  return (
    <header className="site-header">
      <a className="skip-link" href="#main">Skip to content</a>
      <div className="site-header__inner">
        <Link href="/" className="wordmark" aria-label={`${portfolio.name}, home`}>
          <span className="wordmark__name">{portfolio.name}</span>
          <span className="wordmark__role">{portfolio.descriptor}</span>
        </Link>
        <nav className="site-nav" aria-label="Primary">
          <ul>
            {NAV.map((item) => (
              <li key={item.href}>
                <Link href={item.href}>{item.label}</Link>
              </li>
            ))}
          </ul>
        </nav>
      </div>
    </header>
  );
}
