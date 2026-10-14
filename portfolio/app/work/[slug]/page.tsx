import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { PLACEHOLDER_SLUG, getAllProjectSlugs, getProject, getProjectById, getAsset, getHeroAsset, getIndexAsset, getClaims, visibleAssets, lensById } from "@/lib/content";
import Picture from "@/components/Picture";
import LensTags from "@/components/LensTags";
import DraftBadge from "@/components/DraftBadge";
import { STATUS_LABEL } from "@/components/WorkCard";
import type { Asset, Claim, ProjectBundle } from "@/content/types";

export const dynamicParams = false;

export function generateStaticParams() {
  return getAllProjectSlugs().map((slug) => ({ slug }));
}

type Props = { params: Promise<{ slug: string }> };

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { slug } = await params;
  const bundle = getProject(slug);
  if (!bundle) return {};
  return { title: bundle.project.title, description: bundle.project.thesis };
}

function ClaimList({ claims }: { claims: Claim[] }) {
  if (!claims.length) return null;
  return (
    <ul className="claims">
      {claims.map((claim) => (
        <li key={claim.id} className={claim.status === "awaiting" ? "claim--awaiting" : undefined}>
          {claim.wording}
          {claim.status === "awaiting" && <> <span className="draft-marker">Awaiting verification</span></>}
        </li>
      ))}
    </ul>
  );
}

// Editorial opening: the hero image sits beside the title, proposition, and the In Brief text,
// so the first screen reads as one spread. Projects without a short summary lead with the first
// paragraph of their challenge.
function Opening({ bundle }: { bundle: ProjectBundle }) {
  const { project, narrative } = bundle;
  const hero = getHeroAsset(bundle);
  const brief = narrative.summary?.length ? narrative.summary : narrative.challenge.slice(0, 1);
  return (
    <header className="project-opening">
      <div className="project-opening__media">
        {hero ? <Picture asset={hero} priority sizes="(min-width: 900px) 52vw, 100vw" showLens /> : <div className="picture__placeholder">Hero image pending</div>}
      </div>
      <div className="project-opening__text">
        <p className="tag">
          {project.tier === "core" ? `${String(project.sequence).padStart(2, "0")} ${project.portfolioRole}` : project.portfolioRole}
          {project.status !== "completed" && <> <span className="tag tag--status">{STATUS_LABEL[project.status]}</span></>}
        </p>
        {project.permission === "pending" && <DraftBadge note={project.permissionNote} />}
        <h1 className="project-hero__title">{project.title}</h1>
        <p className="project-hero__thesis">{project.thesis}</p>
        {brief.length > 0 && (
          <div className="project-opening__brief">
            <p className="tag">In brief</p>
            {brief.map((p, i) => <p key={i}>{p}</p>)}
          </div>
        )}
        <ClaimList claims={getClaims(bundle, "context")} />
        <LensTags lenses={project.lenses} />
      </div>
    </header>
  );
}

function Glance({ bundle }: { bundle: ProjectBundle }) {
  const { project } = bundle;
  return (
    <dl className="glance" aria-label="At a glance">
      {project.clientDisplayName && <div className="glance__item"><dt>Client</dt><dd>{project.clientDisplayName}</dd></div>}
      {project.location && <div className="glance__item"><dt>Location</dt><dd>{project.location}</dd></div>}
      {project.years && <div className="glance__item"><dt>Years</dt><dd>{project.years}</dd></div>}
      <div className="glance__item"><dt>Status</dt><dd>{STATUS_LABEL[project.status]}{project.statusNote ? `. ${project.statusNote}` : ""}</dd></div>
      <div className="glance__item glance__item--wide"><dt>Role</dt><dd>{project.role}<ClaimList claims={getClaims(bundle, "role")} /></dd></div>
      {project.scope && <div className="glance__item glance__item--wide"><dt>Scope</dt><dd>{project.scope}</dd></div>}
      <div className="glance__item"><dt>Practice</dt><dd>{project.practice}</dd></div>
      {project.team.length > 0 && <div className="glance__item"><dt>Team</dt><dd>{project.team.join(", ")}</dd></div>}
      {project.collaborators.length > 0 && <div className="glance__item"><dt>Collaborators</dt><dd>{project.collaborators.join("; ")}</dd></div>}
      <div className="glance__item"><dt>Lenses</dt><dd><LensTags lenses={project.lenses} /></dd></div>
    </dl>
  );
}

function ProjectInfo({ bundle }: { bundle: ProjectBundle }) {
  return (
    <section className="project-section project-info" aria-labelledby="project-info">
      <div className="project-section__head"><p className="tag">Project information</p><h2 id="project-info" className="section__title">At a glance</h2></div>
      <Glance bundle={bundle} />
      <Credits bundle={bundle} />
    </section>
  );
}

// Selected press: a magazine cover shown uncropped beside the note, linked to the issue.
function FeaturedPublication({ bundle }: { bundle: ProjectBundle }) {
  const publication = bundle.narrative.featuredPublication;
  if (!publication) return null;
  const asset = getAsset(bundle, publication.assetId);
  if (!asset) return null;
  return (
    <section className="project-section" aria-labelledby="featured-publication">
      <div className="spread spread--media-left">
        <div className="spread__text">
          <div className="project-section__head"><p className="tag">Selected press</p><h2 id="featured-publication" className="section__title">{publication.title}</h2></div>
          <div className="prose">
            <p>{publication.description}</p>
            <p><a href={publication.url} className="text-link" data-sweep>View the magazine issue</a></p>
            <p className="picture__credit">{asset.credit}</p>
          </div>
        </div>
        <div className="spread__media">
          <a href={publication.url} aria-label={`${publication.title}: view the magazine issue`}>
            <Picture asset={asset} showCaption={false} sizes="(min-width: 900px) 40vw, 100vw" />
          </a>
        </div>
      </div>
    </section>
  );
}

function Credits({ bundle }: { bundle: ProjectBundle }) {
  const { project, narrative } = bundle;
  const credits = getClaims(bundle, "credits");
  return (
    <div className="project-info__credits">
      <p className="tag">Credits</p>
      <dl className="credits">
        <div><dt>Originating practice</dt><dd>{project.practice}</dd></div>
        <div><dt>Personal involvement</dt><dd>{narrative.involvement}</dd></div>
        {project.team.length > 0 && <div><dt>Team</dt><dd><ul>{project.team.map((t) => <li key={t}>{t}</li>)}</ul></dd></div>}
        {project.collaborators.length > 0 && <div><dt>Collaborators</dt><dd><ul>{project.collaborators.map((c) => <li key={c}>{c}</li>)}</ul></dd></div>}
        <div><dt>Photography and imagery</dt><dd>{[narrative.photographyCredit, narrative.imageCredit].filter(Boolean).join(" ") || "See captions"}</dd></div>
        {credits.length > 0 && <div><dt>Further credits</dt><dd><ClaimList claims={credits} /></dd></div>}
      </dl>
    </div>
  );
}

function Related({ bundle }: { bundle: ProjectBundle }) {
  const related = getProjectById(bundle.project.relatedProject);
  if (!related) return null;
  const asset = getIndexAsset(related);
  return (
    <section className="related" aria-labelledby="related">
      <p className="tag">Related project</p>
      <Link href={`/work/${related.project.slug}/`} className="related__link">
        {asset && <Picture asset={asset} showCaption={false} fit="cover" sizes="(min-width: 800px) 45vw, 100vw" />}
        <div>
          <h2 id="related" className="section__title">{related.project.title}</h2>
          <p className="lede">{related.project.thesis}</p>
          <LensTags lenses={related.project.lenses} />
        </div>
      </Link>
    </section>
  );
}

function DecisionBlocks({ bundle }: { bundle: ProjectBundle }) {
  if (!bundle.decisions.length) return null;
  return (
    <section className="project-section" aria-labelledby="decisions">
      <div className="project-section__head"><p className="tag">Decisive choices</p><h2 id="decisions" className="section__title">{bundle.decisions.length > 1 ? "The decisions that shaped the outcome" : "The decision that shaped the outcome"}</h2></div>
      {bundle.decisions.map((decision, index) => (
        <div className="decision" key={decision.id}>
          <div>
            <h3 className="decision__title"><span className="decision__index">{index + 1}</span>{decision.title}</h3>
            <dl>
              <div><dt>Question</dt><dd>{decision.question}</dd></div>
              <div><dt>Choice</dt><dd>{decision.choice}</dd></div>
              <div><dt>Reason</dt><dd>{decision.rationale}</dd></div>
              <div><dt>Tradeoff</dt><dd>{decision.tradeoff}</dd></div>
              {decision.personalContribution && <div><dt>My part</dt><dd>{decision.personalContribution}</dd></div>}
            </dl>
          </div>
          <div className="decision__media">
            {decision.assetIds.map((id) => {
              const asset = getAsset(bundle, id);
              return asset ? <Picture key={id} asset={asset} sizes="(min-width: 900px) 55vw, 100vw" /> : null;
            })}
          </div>
        </div>
      ))}
    </section>
  );
}

function Section({ id, tag, title, asset, side, children }: { id: string; tag: string; title: string; asset?: Asset | null; side: "left" | "right"; children: React.ReactNode }) {
  if (!asset) {
    return (
      <section className="project-section" aria-labelledby={id}>
        <div className="grid-2">
          <div className="project-section__head"><p className="tag">{tag}</p><h2 id={id} className="section__title">{title}</h2></div>
          <div className="prose">{children}</div>
        </div>
      </section>
    );
  }
  return (
    <section className="project-section" aria-labelledby={id}>
      <div className={`spread ${side === "left" ? "spread--media-left" : ""}`}>
        <div className="spread__text">
          <div className="project-section__head"><p className="tag">{tag}</p><h2 id={id} className="section__title">{title}</h2></div>
          <div className="prose">{children}</div>
        </div>
        <div className="spread__media"><Picture asset={asset} sizes="(min-width: 900px) 50vw, 100vw" showLens /></div>
      </div>
    </section>
  );
}

// Remaining images flow as a two-column mosaic that keeps each image's own proportions.
function Gallery({ assets, title }: { assets: ProjectBundle["assets"]; title: string }) {
  if (!assets.length) return null;
  return (
    <section className="project-section" aria-labelledby="gallery">
      <div className="project-section__head"><p className="tag">Gallery</p><h2 id="gallery" className="section__title">{title}</h2></div>
      <div className="gallery">
        {assets.map((asset) => <Picture key={asset.id} asset={asset} sizes="(min-width: 800px) 50vw, 100vw" showLens />)}
      </div>
    </section>
  );
}

function FullTemplate({ bundle }: { bundle: ProjectBundle }) {
  const { project, narrative, decisions } = bundle;
  const assets = visibleAssets(bundle);
  const usedIds = new Set<string>([project.heroAssetId, ...decisions.flatMap((d) => d.assetIds), ...(narrative.scaleTranslation.map((s) => s.assetId).filter(Boolean) as string[])]);
  const pool = assets.filter((a) => !usedIds.has(a.id) && a.id !== narrative.featuredPublication?.assetId);
  // Each narrative section takes the next unused image and sits beside it, alternating sides.
  const next = () => pool.shift() ?? null;
  const challengeImg = next();
  const visionImg = next();
  const leadershipImg = next();
  const outcomeImg = next();
  return (
    <article className="wrap">
      <Opening bundle={bundle} />
      <FeaturedPublication bundle={bundle} />

      <Section id="challenge" tag="Context" title="The challenge" asset={narrative.summary?.length ? challengeImg : null} side="right">
        {narrative.challenge.map((p, i) => <p key={i}>{p}</p>)}
        <ClaimList claims={getClaims(bundle, "context")} />
      </Section>

      <Section id="vision" tag="Insight and vision" title="The idea that guided the team" asset={visionImg} side="left">
        {narrative.insight.map((p, i) => <p key={`i-${i}`} className="statement">{p}</p>)}
        {narrative.vision.map((p, i) => <p key={`v-${i}`}>{p}</p>)}
      </Section>

      <DecisionBlocks bundle={bundle} />

      <section className="project-section" aria-labelledby="scales">
        <div className="project-section__head"><p className="tag">Translation across scales</p><h2 id="scales" className="section__title">How the idea changed form and stayed itself</h2></div>
        <div className="scale-sequence">
          {narrative.scaleTranslation.map((step, index) => {
            const asset = getAsset(bundle, step.assetId);
            return (
              <div className={`scale-step ${asset ? "" : "scale-step--text-only"}`} key={index}>
                {asset && <div className="scale-step__media"><Picture asset={asset} sizes="(min-width: 900px) 66vw, 100vw" /></div>}
                <div className="scale-step__text">
                  <p className="tag tag--lens">{lensById[step.lens].name}</p>
                  <p className="scale-step__caption">{step.caption}</p>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      <Section id="leadership" tag="Leadership and collaboration" title="What was led, and by whom" asset={leadershipImg} side="right">
        {narrative.leadership.map((p, i) => <p key={i}>{p}</p>)}
        {narrative.leadershipMoment && (<><p className="tag">A moment of alignment</p><p>{narrative.leadershipMoment}</p></>)}
        <ClaimList claims={getClaims(bundle, "leadership")} />
      </Section>

      <Section id="outcome" tag="Outcome and reflection" title="What was delivered" asset={outcomeImg} side="left">
        {narrative.outcome.map((p, i) => <p key={i}>{p}</p>)}
        <ClaimList claims={getClaims(bundle, "outcome")} />
        {narrative.reflection && (<><p className="tag">Reflection</p><p className="statement statement--small">{narrative.reflection}</p></>)}
      </Section>

      <Gallery assets={pool} title="More views" />
      <ProjectInfo bundle={bundle} />
      <Related bundle={bundle} />
    </article>
  );
}

function LightTemplate({ bundle }: { bundle: ProjectBundle }) {
  const { project, narrative } = bundle;
  const assets = visibleAssets(bundle).filter((a) => a.id !== project.heroAssetId && a.id !== narrative.featuredPublication?.assetId && !bundle.decisions.some((d) => d.assetIds.includes(a.id)));
  return (
    <article className="wrap">
      <Opening bundle={bundle} />
      <FeaturedPublication bundle={bundle} />
      {bundle.decisions.length > 0 && <DecisionBlocks bundle={{ ...bundle, decisions: bundle.decisions.slice(0, 1) }} />}
      <Gallery assets={assets} title="Views" />
      <ProjectInfo bundle={bundle} />
      <Related bundle={bundle} />
    </article>
  );
}

export default async function ProjectPage({ params }: Props) {
  const { slug } = await params;
  const bundle = getProject(slug);
  if (!bundle && slug === PLACEHOLDER_SLUG) {
    return (
      <div className="wrap">
        <section className="page-head">
          <p className="tag">Work</p>
          <h1 className="page-head__title">Case studies are being cleared for publication</h1>
          <p className="lede">Project pages appear here once client and studio permission is confirmed. In the meantime, the approach and contact pages are open.</p>
          <div className="actions">
            <Link href="/approach/" className="button" data-sweep>Read the approach</Link>
            <Link href="/contact/" className="text-link" data-sweep>Get in touch</Link>
          </div>
        </section>
      </div>
    );
  }
  if (!bundle) notFound();
  return bundle.project.caseStudy === "full" ? <FullTemplate bundle={bundle} /> : <LightTemplate bundle={bundle} />;
}
