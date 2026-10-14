import Link from "next/link";
import { getCoreProjects, getLandingTiles, getLensCounts, getProfileAsset, getProfileClaimsById, portfolio, profile, approachSteps } from "@/lib/content";
import { getDownloads } from "@/lib/files";
import { withBasePath } from "@/lib/basePath";
import Picture from "@/components/Picture";
import LensTags from "@/components/LensTags";
import ScrollStage from "@/components/ScrollStage";
import LensMarquee from "@/components/LensMarquee";
import Portrait from "@/components/Portrait";
import WorkCard from "@/components/WorkCard";
import { LensProvider, LensKey } from "@/components/LensContext";
import { lensIntro, lensHeading } from "@/content/lenses";

// Home features the first six core projects in sequence; the rest live on the Work page.
const FEATURED_LIMIT = 6;

export default function HomePage() {
  const tiles = getLandingTiles();
  const featured = getCoreProjects().slice(0, FEATURED_LIMIT);
  const counts = getLensCounts();
  const portrait = getProfileAsset(profile.portraitAssetId);
  const recognition = getProfileClaimsById(profile.recognitionClaimIds);
  const downloads = getDownloads();
  const mailto = `mailto:${portfolio.email}?subject=${encodeURIComponent(portfolio.emailSubject)}`;

  return (
    <>
      {/* 1. Stage: statement at the center of a mouse-panned canvas with the tile field around it */}
      <section aria-labelledby="statement" className="stage-section">
        <ScrollStage>
          <div className="stage__statement" data-statement>
            <p className="stage__identity"><strong>{portfolio.name}</strong> <span>{profile.currentTitle}</span></p>
            <h1 id="statement" className="stage__headline">{portfolio.statement}</h1>
            <p className="stage__subhead">{portfolio.tagline}</p>
            <p className="stage__body">{portfolio.statementBody}</p>
            <p className="stage__actions">
              <Link href="/work/" className="button" data-sweep>Explore selected work</Link>
              <Link href="/approach/" className="button" data-sweep>How I approach creative direction</Link>
            </p>
          </div>
          <ol className="stage__field" aria-label="Project tiles">
            {tiles.map((tile) => (
              <li key={tile.key} className={`tile tile--size-${tile.bundle.project.tileSize}`} data-tile data-size={tile.size}>
                <Link href={`/work/${tile.bundle.project.slug}/`} className="tile__link cursor-tile">
                  <div className="tile__media">
                    {tile.asset ? <Picture asset={tile.asset} showCaption={false} fit="cover" sizes="(min-width: 720px) 40vw, 50vw" priority={tile.spec.order <= 2 && tile.key.endsWith("-0")} /> : <div className="picture__placeholder">Image pending</div>}
                  </div>
                  <span className="tile__name">{tile.label}</span>
                  <LensTags lenses={tile.bundle.project.lenses} max={2} className="tile__lenses" />
                </Link>
              </li>
            ))}
          </ol>
        </ScrollStage>
        <a href="#lenses" className="scroll-cue" aria-label="Scroll to the work" data-stage-avoid>
          <span className="scroll-cue__text" aria-hidden="true">Scroll</span>
          <svg className="scroll-cue__arrow" viewBox="0 0 24 40" aria-hidden="true" focusable="false">
            <path d="M12 2v34M3 27l9 9 9-9" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </a>
      </section>

      {/* 2. Leadership proof, straight after the first visual introduction */}
      <section className="leadership-proof wrap" aria-labelledby="leadership-proof-heading" data-reveal>
        <h2 id="leadership-proof-heading" className="section__title">{portfolio.leadershipHeading}</h2>
        <div className="leadership-proof__body">
          {portfolio.leadershipProof.map((p, i) => <p key={i}>{p}</p>)}
        </div>
        <ul className="leadership-proof__figures" aria-label="Leadership scope">
          <li><strong>~11</strong><span>Designers across disciplines</span></li>
          <li><strong>7</strong><span>Concurrent projects</span></li>
          <li><strong>15+</strong><span>Years in architecture, interiors, and experience</span></li>
        </ul>
      </section>

      <LensProvider>
        {/* 2. Selected work: sticky heading, six cards beside their text */}
        <section className="work-section wrap" aria-labelledby="work-heading">
          <div className="work-section__sticky" data-reveal>
            <h2 id="work-heading" className="work-section__heading">Work</h2>
            <p className="work-section__range">&copy;{portfolio.workRangeLabel}</p>
            <p className="work-section__intro">
              I help teams carry a clear idea from concept into the places and experiences people encounter every day, across workplaces, shared amenities, retail environments and brand platforms.
            </p>
          </div>
          <div className="work-section__cards">
            {featured.length ? featured.map((bundle, i) => <WorkCard key={bundle.project.id} bundle={bundle} index={i} />) : (
              <p className="empty-state">Core projects appear here once their permission is confirmed. Build with NEXT_PUBLIC_SHOW_DRAFTS=true to preview them.</p>
            )}
            <p data-reveal><Link href="/work/" className="button" data-sweep>View All Work</Link></p>
          </div>
        </section>
        {/* 3. Lens marquee and lens key */}
        <section id="lenses" className="section section--marquee" aria-labelledby="lenses-heading">
          <LensMarquee />
          <div className="wrap">
            <h2 id="lenses-heading" className="section__title lens-heading" data-reveal>{lensHeading}</h2>
            <p className="lede lens-lede" data-reveal>{lensIntro}</p>
            <LensKey counts={counts} compact mode="dim" />
          </div>
        </section>

        {/* 3. Full-bleed portrait */}
        {portrait && (
          <Portrait>
            <Picture asset={portrait} showCaption={false} fit="cover" sizes="100vw" />
          </Portrait>
        )}

        {/* 4. About band on the accent */}
        <section className="about-band" data-header-invert aria-labelledby="about-heading">
          <div className="wrap">
            <h2 id="about-heading" className="visually-hidden">About</h2>
            <div className="about-band__top" data-reveal>
              <p className="about-band__bio">{profile.bio}</p>
              <p className="about-band__statement">{profile.leadershipStatement}</p>
            </div>
            <div className="band-row">
              <p className="band-row__label" data-reveal>Experience</p>
              <div>
                <ol className="timeline">
                  {profile.experience.map((item) => (
                    <li key={`${item.title}-${item.years}`} className="timeline__row line-row" data-reveal data-sweep>
                      <span>{item.title}</span><span>{item.practice}</span><span className="timeline__years">{item.years}</span><span className="line-row__line" aria-hidden="true" />
                    </li>
                  ))}
                </ol>
                <p className="band-row__link" data-reveal><Link href="/about/" className="text-link text-link--on-accent" data-sweep>More about me</Link></p>
              </div>
            </div>
            {recognition.length > 0 && (
              <div className="band-row">
                <p className="band-row__label" data-reveal>Recognition Highlights</p>
                <ul className="ruled-list">
                  {recognition.map((claim) => (
                    <li key={claim.id} className={`line-row ${claim.status === "awaiting" ? "claim--awaiting" : ""}`} data-reveal data-sweep>
                      {claim.url ? <a href={claim.url} rel="noopener" data-sweep className="sweep-link">{claim.wording}</a> : claim.wording}
                      <span className="line-row__line" aria-hidden="true" />
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </section>

      </LensProvider>

      {/* 6. Approach preview and invitation */}
      <section className="section wrap" aria-labelledby="approach-heading" data-reveal>
        <p className="tag">Approach</p>
        <h2 id="approach-heading" className="section__title">Direction is established early and carried through teams</h2>
        <ol className="step-row">
          {approachSteps.map((step) => (
            <li key={step.id}><span className="step-row__num">{String(step.number).padStart(2, "0")}</span>{step.title}</li>
          ))}
        </ol>
        <p><Link href="/approach/" className="text-link" data-sweep>Read the approach</Link></p>
      </section>

      <section className="section wrap section--invite" aria-labelledby="invite-heading" data-reveal>
        <p className="tag">Next</p>
        <h2 id="invite-heading" className="section__title">Let&apos;s shape what comes next</h2>
        <p className="lede">{portfolio.availability}</p>
        <p className="tag">{portfolio.internationalAvailability}</p>
        <div className="actions">
          <a href={mailto} className="button button--accent" data-sweep>Get in touch</a>
          {downloads.portfolioPdf && <a href={withBasePath(downloads.portfolioPdf)} className="button" data-sweep>Portfolio PDF</a>}
        </div>
      </section>
    </>
  );
}
