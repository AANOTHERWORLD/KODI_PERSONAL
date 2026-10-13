import Link from "next/link";
import { portfolio } from "@/lib/content";
import { getDownloads } from "@/lib/files";
import { withBasePath } from "@/lib/basePath";

export default function SiteFooter() {
  const downloads = getDownloads();
  const year = new Date().getFullYear();
  return (
    <footer className="site-footer">
      <div className="site-footer__inner">
        <div className="site-footer__col">
          <p className="site-footer__positioning">{portfolio.positioning}</p>
          <p className="site-footer__location">{portfolio.location}</p>
        </div>
        <div className="site-footer__col">
          <ul className="site-footer__links">
            <li><a href={`mailto:${portfolio.email}`}>{portfolio.email}</a></li>
            <li><a href={portfolio.linkedin} rel="me noopener">LinkedIn</a></li>
            {downloads.portfolioPdf && <li><a href={withBasePath(downloads.portfolioPdf)}>Portfolio PDF</a></li>}
            {downloads.cvPdf && <li><a href={withBasePath(downloads.cvPdf)}>CV</a></li>}
            <li><Link href="/work/">Selected Work</Link></li>
          </ul>
          <p className="site-footer__copyright">
            Copyright {year} {portfolio.copyrightHolder}. Project imagery remains the property of its credited owners.
          </p>
        </div>
      </div>
    </footer>
  );
}
