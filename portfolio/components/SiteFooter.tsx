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
          <p className="site-footer__headline">Let&apos;s shape what comes next</p>
          <a href={mailto} className="footer-link" data-sweep>Email Me</a>
          <svg className="site-footer__mark" viewBox="0 0 100 100" aria-hidden="true" focusable="false">
            <g stroke="currentColor" strokeWidth="9" strokeLinecap="round">
              <line x1="50" y1="8" x2="50" y2="92" />
              <line x1="13.6" y1="29" x2="86.4" y2="71" />
              <line x1="13.6" y1="71" x2="86.4" y2="29" />
            </g>
          </svg>
        </div>
        <div className="site-footer__cols">
          <div>
            <p className="site-footer__label">Navigation</p>
            <ul>
              <li><Link href="/" className="footer-link" data-sweep>Home</Link></li>
              <li><Link href="/work/" className="footer-link" data-sweep>Work</Link></li>
              <li><Link href="/approach/" className="footer-link" data-sweep>Approach</Link></li>
              <li><Link href="/about/" className="footer-link" data-sweep>About</Link></li>
              {downloads.portfolioPdf && <li><a href={withBasePath(downloads.portfolioPdf)} className="footer-link" data-sweep>Portfolio PDF</a></li>}
              {downloads.cvPdf && <li><a href={withBasePath(downloads.cvPdf)} className="footer-link" data-sweep>CV</a></li>}
            </ul>
          </div>
          {(portfolio.linkedin || portfolio.instagram) && (
            <div>
              <p className="site-footer__label">Follow me</p>
              <ul>
                {portfolio.linkedin && <li><a href={portfolio.linkedin} rel="me noopener" className="footer-link" data-sweep>LinkedIn</a></li>}
                {portfolio.instagram && <li><a href={portfolio.instagram} rel="me noopener" className="footer-link" data-sweep>Instagram</a></li>}
              </ul>
            </div>
          )}
          <div>
            <p className="site-footer__label">Contact</p>
            <p className="site-footer__contact">{portfolio.location}</p>
            <p className="site-footer__contact"><a href={mailto} className="footer-link" data-sweep>{portfolio.email}</a></p>
            <p className="site-footer__copyright">&copy;{year} {portfolio.copyrightHolder}</p>
          </div>
        </div>
      </div>
    </footer>
  );
}
