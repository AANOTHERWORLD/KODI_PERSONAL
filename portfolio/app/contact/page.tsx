import type { Metadata } from "next";
import { portfolio } from "@/lib/content";
import { getDownloads } from "@/lib/files";
import { withBasePath } from "@/lib/basePath";

export const metadata: Metadata = {
  title: "Contact",
  description: "Get in touch about creative leadership opportunities and collaboration.",
};

export default function ContactPage() {
  const downloads = getDownloads();
  return (
    <div className="wrap">
      <section className="hero" aria-labelledby="contact-title">
        <p className="kicker">Contact</p>
        <h1 id="contact-title" className="hero__headline">Let&apos;s talk about creative leadership</h1>
        <p className="hero__positioning">
          I am interested in Creative Director roles and in collaborations where a shared idea has to hold across strategy, place, interiors, and brand. Email is the fastest way to reach me.
        </p>
        <ul className="contact-links">
          <li><a href={`mailto:${portfolio.email}`} data-cursor="ring">{portfolio.email}</a></li>
          <li><a href={portfolio.linkedin} rel="me noopener" data-cursor="ring">LinkedIn</a></li>
          {downloads.portfolioPdf && <li><a href={withBasePath(downloads.portfolioPdf)} data-cursor="ring">Portfolio PDF</a></li>}
          {downloads.cvPdf && <li><a href={withBasePath(downloads.cvPdf)} data-cursor="ring">CV</a></li>}
        </ul>
        <p className="site-footer__location" style={{ marginTop: "var(--space-4)" }}>{portfolio.location}</p>
      </section>
    </div>
  );
}
