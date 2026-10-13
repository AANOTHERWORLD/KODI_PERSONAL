import Link from "next/link";
import { getLeadProject, getHomeFeatures, getProjects, getHeroAsset, getIndexAsset, portfolio, lenses } from "@/lib/content";
import { lensIntro } from "@/content/lenses";
import { getDownloads } from "@/lib/files";
import { withBasePath } from "@/lib/basePath";
import Picture from "@/components/Picture";
import LensTags from "@/components/LensTags";
import { HomeLensProvider, LensAwareEntry, LensKey } from "@/components/HomeLens";
import type { LensId } from "@/content/types";

export default function HomePage() {
  const lead = getLeadProject();
  const features = getHomeFeatures(3);
  const all = getProjects();
  const downloads = getDownloads();
  const counts = Object.fromEntries(lenses.map((l) => [l.id, all.filter((b) => b.project.lenses.includes(l.id)).length])) as Record<LensId, number>;
  const leadAsset = lead ? getHeroAsset(lead) : null;

  return (
    <>
      {/* 1. Opening */}
      <section className="hero wrap" aria-labelledby="hero-title">
        <p className="hero__name">{portfolio.name}, {portfolio.descriptor}</p>
        <h1 id="hero-title" className="hero__headline">{portfolio.headline}</h1>
        <p className="hero__positioning">{portfolio.positioning}</p>
        <div className="hero__actions">
          <Link href="/work/" className="button" data-cursor="ring">View selected work</Link>
          <Link href="/approach/" className="text-link">How the direction is set</Link>
        </div>
      </section>

      {/* 2. Lead work */}
      {lead && (
        <section className="section wrap" aria-labelledby="lead-title">
          <p className="kicker">Lead work</p>
          <Link href={`/work/${lead.project.slug}/`} className="lead-work__link" data-cursor="ring">
            {leadAsset && <Picture asset={leadAsset} showCaption={false} fit="cover" priority sizes="(min-width: 1280px) 1280px, 100vw" />}
            <div className="lead-work__line">
              <h2 id="lead-title" className="lead-work__title">{lead.project.title}</h2>
              <p className="lead-work__idea">{lead.project.thesis}</p>
              <p className="lead-work__role">
                {lead.project.role}
                {lead.project.permission === "pending" && <> <span className="draft-marker">Draft: permission pending</span></>}
              </p>
            </div>
          </Link>
        </section>
      )}

      <HomeLensProvider>
        {/* 3. Selected work */}
        <section className="section wrap" aria-labelledby="selected-title">
          <p className="kicker">Selected work</p>
          <h2 id="selected-title">Three projects, three scales</h2>
          {features.length ? (
            <div className="feature-list">
              {features.map((bundle) => {
                const asset = getIndexAsset(bundle);
                return (
                  <LensAwareEntry key={bundle.project.id} lensIds={bundle.project.lenses} className="feature">
                    <Link href={`/work/${bundle.project.slug}/`} className="feature__link" data-cursor="ring">
                      {asset && <Picture asset={asset} showCaption={false} fit="cover" sizes="(min-width: 900px) 33vw, 100vw" />}
                      <h3 className="feature__title">{bundle.project.title}</h3>
                      <p className="feature__thesis">{bundle.project.thesis}</p>
                    </Link>
                    <LensTags lenses={bundle.project.lenses} />
                  </LensAwareEntry>
                );
              })}
            </div>
          ) : (
            <p className="empty-state">Featured projects appear here once their permission is confirmed. Run a draft build to preview them.</p>
          )}
          <p style={{ marginTop: "var(--space-4)" }}>
            <Link href="/work/" className="button" data-cursor="ring">The full selection</Link>
          </p>
        </section>

        {/* 4. Connected practice */}
        <section className="section wrap" aria-labelledby="lens-title">
          <p className="kicker">Connected practice</p>
          <h2 id="lens-title">Four lenses, one direction</h2>
          <p className="lede">{lensIntro}</p>
          <LensKey counts={counts} />
        </section>
      </HomeLensProvider>

      {/* 5. Leadership preview */}
      <section className="section wrap" aria-labelledby="leadership-title">
        <div className="grid-2">
          <div>
            <p className="kicker">Leadership</p>
            <h2 id="leadership-title">Direction is established early and carried through delivery</h2>
          </div>
          <div>
            <p className="lede">
              I set the idea and the criteria for judging decisions against it, then guide the team through critique, alignment, and the compromises of delivery. The method repeats from project to project. Its results differ every time.
            </p>
            <Link href="/approach/" className="text-link">Read the approach</Link>
          </div>
        </div>
      </section>

      {/* 6. Invitation */}
      <section className="section wrap" aria-labelledby="invite-title">
        <p className="kicker">Next</p>
        <h2 id="invite-title">Start a conversation</h2>
        <p className="lede">{portfolio.availability}</p>
        <div className="hero__actions">
          <a href={`mailto:${portfolio.email}`} className="button button--accent" data-cursor="ring">Email {portfolio.name.split(" ")[0]}</a>
          {downloads.portfolioPdf && <a href={withBasePath(downloads.portfolioPdf)} className="button" data-cursor="ring">Portfolio PDF</a>}
          <Link href="/contact/" className="text-link">Contact details</Link>
        </div>
      </section>
    </>
  );
}
