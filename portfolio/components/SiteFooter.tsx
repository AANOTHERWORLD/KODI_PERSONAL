import Link from "next/link";
import { portfolio } from "@/lib/content";
import { getDownloads } from "@/lib/files";
import { withBasePath } from "@/lib/basePath";

export default function SiteFooter() {
  const downloads = getDownloads();
  const year = new Date().getFullYear();
  const mailto = `mailto:${portfolio.email}?subject=${encodeURIComponent(portfolio.emailSubject)}`;
  return (
    <footer className="site-footer">
      <div className="site-footer__inner">
        <div>
          <p className="site-footer__positioning">{portfolio.positioning}</p>
          <p className="tag">{portfolio.location}</p>
        </div>
        <div>
          <ul className="site-footer__links">
            <li><a href={mailto} data-cursor="ring">Email Me</a></li>
            <li><a href={portfolio.linkedin} rel="me noopener" data-cursor="ring">LinkedIn</a></li>
            <li><a href={portfolio.instagram} rel="me noopener" data-cursor="ring">Instagram</a></li>
            {downloads.portfolioPdf && <li><a href={withBasePath(downloads.portfolioPdf)} data-cursor="ring">Portfolio PDF</a></li>}
            {downloads.cvPdf && <li><a href={withBasePath(downloads.cvPdf)} data-cursor="ring">CV</a></li>}
            <li><Link href="/work/" data-cursor="ring">Work</Link></li>
          </ul>
          <p className="site-footer__copyright">
            Copyright {year} {portfolio.copyrightHolder}. Project imagery remains the property of its credited owners.
          </p>
        </div>
      </div>
    </footer>
  );
}
