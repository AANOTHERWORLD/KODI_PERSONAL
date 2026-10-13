import Link from "next/link";
import { getCoreProjects, getExtendedProjects, getLandingTiles, getStageHeightVh, getLensCounts, getProfileAsset, getProfileClaimsById, portfolio, profile, approachSteps } from "@/lib/content";
import { getDownloads } from "@/lib/files";
import { withBasePath } from "@/lib/basePath";
import Picture from "@/components/Picture";
import LensTags from "@/components/LensTags";
import ScrollStage from "@/components/ScrollStage";
import LensMarquee from "@/components/LensMarquee";
import Portrait from "@/components/Portrait";
import WorkCard, { tilePx } from "@/components/WorkCard";
import { LensProvider, LensKey } from "@/components/LensContext";
import { lensIntro } from "@/content/lenses";

export default function HomePage() {
  const tiles = getLandingTiles();
  const core = getCoreProjects();
  const extended = getExtendedProjects();
  const counts = getLensCounts();
  const portrait = getProfileAsset(profile.portraitAssetId);
  const recognition = getProfileClaimsById(profile.recognitionClaimIds);
  const downloads = getDownloads();
  const mailto = `mailto:${portfolio.email}?subject=${encodeURIComponent(portfolio.emailSubject)}`;

  return (
    <>
      {/* 1. Scroll stage: fixed statement and drifting tile field */}
      <section aria-labelledby="statement" className="stage-section">
        <ScrollStage heightVh={getStageHeightVh()}>
          <div className="stage__statement" data-statement>
            <p className="tag">{portfolio.name}, {portfolio.descriptor}</p>
            <h1 id="statement" className="stage__headline">{portfolio.statement}</h1>
          </div>
          <ol className="stage__field" aria-label="Project tiles">
            {tiles.map((tile) => (
              <li
                key={tile.key}
                className={`tile tile--size-${tile.bundle.project.tileSize}`}
                data-tile
                data-depth={tile.spec.depth}
                style={{ "--tile-x": `${tile.spec.x}%`, "--tile-y": `${tile.spec.y}%`, "--tile-w": `${tilePx(tile.bundle.project.tileSize)}px` } as React.CSSProperties}
              >
                <Link href={`/work/${tile.bundle.project.slug}/`} className="tile__link" data-cursor="ring">
                  <div className="tile__media">
                    {tile.asset ? <Picture asset={tile.asset} showCaption={false} fit="cover" sizes="(min-width: 720px) 40vw, 50vw" priority={tile.spec.order <= 2} /> : <div className="picture__placeholder">Image pending</div>}
                  </div>
                  <p className="tile__name">{tile.label}</p>
                  <LensTags lenses={tile.bundle.project.lenses} max={2} className="tile__lenses" />
                </Link>
              </li>
            ))}
          </ol>
        </ScrollStage>
      </section>

      <LensProvider>
        {/* 2. Lens marquee and lens key */}
        <section className="section section--marquee" aria-labelledby="lenses-heading">
          <LensMarquee />
          <div className="wrap">
            <h2 id="lenses-heading" className="visually-hidden">Four lenses</h2>
            <p className="lede">{lensIntro}</p>
            <LensKey counts={counts} compact />
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
            <div className="about-band__top">
              <div>
                <h2 id="about-heading" className="tag tag--on-accent">About</h2>
                <p className="about-band__bio">{profile.bio}</p>
              </div>
              <p className="about-band__statement">{profile.aboutStatement}</p>
            </div>
            <div className="about-band__experience">
              <p className="tag tag--on-accent">Experience</p>
              <ol className="timeline">
                {profile.experience.map((item) => (
                  <li key={`${item.title}-${item.years}`} className="timeline__row">
                    <span>{item.title}</span><span>{item.practice}</span><span>{item.years}</span>
                  </li>
                ))}
              </ol>
            </div>
            {recognition.length > 0 && (
              <div className="about-band__recognition">
                <p className="tag tag--on-accent">Recognition Highlights</p>
                <ul className="ruled-list">
                  {recognition.map((claim) => (
                    <li key={claim.id} className={claim.status === "awaiting" ? "claim--awaiting" : undefined}>
                      {claim.wording}
                      {claim.status === "awaiting" && <> <span className="draft-marker draft-marker--on-accent">Awaiting verification</span></>}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            <p><Link href="/about/" className="text-link text-link--on-accent" data-cursor="ring">More about me</Link></p>
          </div>
        </section>

        {/* 5. Work section: sticky heading, framed cards */}
        <section className="work-section wrap" aria-labelledby="work-heading">
          <div className="work-section__sticky">
            <h2 id="work-heading" className="work-section__heading">Work</h2>
            <p className="tag">&copy;{portfolio.workRangeLabel}</p>
          </div>
          <div className="work-section__cards">
            {core.length ? core.map((bundle, i) => <WorkCard key={bundle.project.id} bundle={bundle} index={i} />) : (
              <p className="empty-state">Core projects appear here once their permission is confirmed. Build with NEXT_PUBLIC_SHOW_DRAFTS=true to preview them.</p>
            )}
            {extended.length > 0 && (
              <div className="more-work">
                <p className="tag">More work</p>
                <div className="more-work__grid">
                  {extended.map((bundle, i) => <WorkCard key={bundle.project.id} bundle={bundle} index={i} variant="small" />)}
                </div>
              </div>
            )}
            <p><Link href="/work/" className="button" data-cursor="ring">View All Work</Link></p>
          </div>
        </section>
      </LensProvider>

      {/* 6. Approach preview and invitation */}
      <section className="section wrap" aria-labelledby="approach-heading">
        <p className="tag">Approach</p>
        <h2 id="approach-heading" className="section__title">Direction is established early and carried through teams</h2>
        <ol className="step-row">
          {approachSteps.map((step) => (
            <li key={step.id}><span className="step-row__num">{String(step.number).padStart(2, "0")}</span>{step.title}</li>
          ))}
        </ol>
        <p><Link href="/approach/" className="text-link" data-cursor="ring">Read the approach</Link></p>
      </section>

      <section className="section wrap section--invite" aria-labelledby="invite-heading">
        <p className="tag">Next</p>
        <h2 id="invite-heading" className="section__title">Start a conversation</h2>
        <p className="lede">{portfolio.availability}</p>
        <div className="actions">
          <a href={mailto} className="button button--accent" data-cursor="ring">Start a conversation</a>
          {downloads.portfolioPdf && <a href={withBasePath(downloads.portfolioPdf)} className="button" data-cursor="ring">Portfolio PDF</a>}
        </div>
      </section>
    </>
  );
}
