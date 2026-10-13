import type { Metadata } from "next";
import localFont from "next/font/local";
import "./globals.css";
import SiteHeader from "@/components/SiteHeader";
import SiteFooter from "@/components/SiteFooter";
import CursorTrail from "@/components/CursorTrail";
import { portfolio, isDraftMode } from "@/lib/content";

// Self-hosted fonts (public/fonts). Fraunces for display, Inter for UI, body, and captions.
const display = localFont({
  src: [
    { path: "../public/fonts/fraunces-normal-latin.woff2", style: "normal", weight: "300 700" },
    { path: "../public/fonts/fraunces-italic-latin.woff2", style: "italic", weight: "300 700" },
  ],
  variable: "--font-display",
  display: "swap",
});

const sans = localFont({
  src: [{ path: "../public/fonts/inter-normal-latin.woff2", style: "normal", weight: "300 700" }],
  variable: "--font-sans",
  display: "swap",
});

export const metadata: Metadata = {
  title: {
    default: `${portfolio.name}, ${portfolio.descriptor}`,
    template: `%s | ${portfolio.name}`,
  },
  description: `${portfolio.headline} ${portfolio.positioning}`,
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  const draft = isDraftMode();
  return (
    <html lang="en" className={`${display.variable} ${sans.variable}`} data-draft={draft || undefined}>
      <body>
        {draft && (
          <p className="draft-banner" role="status">
            Draft preview. Projects, assets, and claims awaiting permission or verification are shown with markers. Production builds exclude them.
          </p>
        )}
        <SiteHeader />
        <main id="main" className="site-main">
          {children}
        </main>
        <SiteFooter />
        <CursorTrail />
      </body>
    </html>
  );
}
