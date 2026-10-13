import Link from "next/link";
import { portfolio } from "@/lib/content";
import { getDownloads } from "@/lib/files";
import { withBasePath } from "@/lib/basePath";

// Dark footer from the prototype: headline with Email Me, Navigation, Follow me, Contact, and
// the smiley mark. Location shows the city only.
export default function SiteFooter() {
  const downloads = getDownloads();
  const year = new Date().getFullYear();
  const mailto = `mailto:${portfolio.email}?subject=${encodeURIComponent(portfolio.emailSubject)}`;
  return (
    <footer className="site-footer" data-header-invert>
      <div className="site-footer__inner">
        <div className="site-footer__lead">
          <p className="site-footer__headline">Let&apos;s talk about working together</p>
          <a href={mailto} className="footer-link" data-cursor="ring">Email Me</a>
          <svg className="site-footer__mark" viewBox="0 0 100 100" aria-hidden="true" focusable="false">
            <circle cx="50" cy="50" r="44" fill="none" stroke="currentColor" strokeWidth="7" />
            <circle cx="56" cy="32" r="6" fill="currentColor" />
            <circle cx="70" cy="56" r="6" fill="currentColor" />
            <path d="M30 34 A26 26 0 0 0 54 72" fill="none" stroke="currentColor" strokeWidth="7" strokeLinecap="round" />
          </svg>
        </div>
        <div className="site-footer__cols">
          <div>
            <p className="site-footer__label">Navigation</p>
            <ul>
              <li><Link href="/" className="footer-link" data-cursor="ring">Home</Link></li>
              <li><Link href="/work/" className="footer-link" data-cursor="ring">Work</Link></li>
              <li><Link href="/approach/" className="footer-link" data-cursor="ring">Approach</Link></li>
              <li><Link href="/about/" className="footer-link" data-cursor="ring">About</Link></li>
              {downloads.portfolioPdf && <li><a href={withBasePath(downloads.portfolioPdf)} className="footer-link" data-cursor="ring">Portfolio PDF</a></li>}
              {downloads.cvPdf && <li><a href={withBasePath(downloads.cvPdf)} className="footer-link" data-cursor="ring">CV</a></li>}
            </ul>
          </div>
          <div>
            <p className="site-footer__label">Follow me</p>
            <ul>
              <li><a href={portfolio.linkedin} rel="me noopener" className="footer-link" data-cursor="ring">LinkedIn</a></li>
              <li><a href={portfolio.instagram} rel="me noopener" className="footer-link" data-cursor="ring">Instagram</a></li>
            </ul>
          </div>
          <div>
            <p className="site-footer__label">Contact</p>
            <p className="site-footer__contact">{portfolio.location}</p>
            <p className="site-footer__contact"><a href={mailto} className="footer-link" data-cursor="ring">{portfolio.email}</a></p>
            <p className="site-footer__copyright">&copy;{year} {portfolio.copyrightHolder}</p>
          </div>
        </div>
      </div>
    </footer>
  );
}
