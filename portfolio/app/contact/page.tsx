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
  const mailto = `mailto:${portfolio.email}?subject=${encodeURIComponent(portfolio.emailSubject)}`;
  return (
    <div className="wrap">
      <section className="page-head" aria-labelledby="contact-title">
        <p className="tag">Contact</p>
        <h1 id="contact-title" className="page-head__title">Let&apos;s shape what comes next</h1>
        <p className="lede">{portfolio.availability} Email is the fastest way to reach me.</p>
        <ul className="contact-links">
          <li><a href={mailto}>{portfolio.email}</a></li>
          {portfolio.linkedin && <li><a href={portfolio.linkedin} rel="me noopener">LinkedIn</a></li>}
          {portfolio.instagram && <li><a href={portfolio.instagram} rel="me noopener">Instagram</a></li>}
          {downloads.portfolioPdf && <li><a href={withBasePath(downloads.portfolioPdf)}>Portfolio PDF</a></li>}
          {downloads.cvPdf && <li><a href={withBasePath(downloads.cvPdf)}>CV</a></li>}
        </ul>
        <p className="tag">{portfolio.location}</p>
      </section>
    </div>
  );
}
