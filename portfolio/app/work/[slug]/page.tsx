import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { PLACEHOLDER_SLUG, getAllProjectSlugs, getProject, getProjectById, getAsset, getHeroAsset, getIndexAsset, getClaims, visibleAssets, lensById } from "@/lib/content";
import Picture from "@/components/Picture";
import LensTags from "@/components/LensTags";
import DraftBadge from "@/components/DraftBadge";
import { STATUS_LABEL } from "@/components/WorkCard";
import type { Claim, ProjectBundle } from "@/content/types";

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

function Opening({ bundle }: { bundle: ProjectBundle }) {
  const { project } = bundle;
  const hero = getHeroAsset(bundle);
  return (
    <header className="project-hero">
      <p className="tag">
        {project.tier === "core" ? `${String(project.sequence).padStart(2, "0")} ${project.portfolioRole}` : project.portfolioRole}
        {project.status !== "completed" && <> <span className="tag tag--status">{STATUS_LABEL[project.status]}</span></>}
      </p>
      {project.permission === "pending" && <DraftBadge note={project.permissionNote} />}
      <h1 className="project-hero__title">{project.title}</h1>
      <p className="project-hero__thesis">{project.thesis}</p>
      <div className="project-hero__media">
        {hero ? <Picture asset={hero} priority sizes="(min-width: 1280px) 1280px, 100vw" showLens /> : <div className="picture__placeholder">Hero image pending</div>}
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

function Credits({ bundle }: { bundle: ProjectBundle }) {
  const { project, narrative } = bundle;
  const credits = getClaims(bundle, "credits");
  return (
    <section className="project-section" aria-labelledby="credits">
      <div className="project-section__head"><p className="tag">Credits</p><h2 id="credits" className="section__title">Who did what</h2></div>
      <dl className="credits">
        <div><dt>Originating practice</dt><dd>{project.practice}</dd></div>
        <div><dt>Personal involvement</dt><dd>{narrative.involvement}</dd></div>
        {project.team.length > 0 && <div><dt>Team</dt><dd><ul>{project.team.map((t) => <li key={t}>{t}</li>)}</ul></dd></div>}
        {project.collaborators.length > 0 && <div><dt>Collaborators</dt><dd><ul>{project.collaborators.map((c) => <li key={c}>{c}</li>)}</ul></dd></div>}
        <div><dt>Photography and imagery</dt><dd>{[narrative.photographyCredit, narrative.imageCredit].filter(Boolean).join(" ") || "See captions"}</dd></div>
        {credits.length > 0 && <div><dt>Further credits</dt><dd><ClaimList claims={credits} /></dd></div>}
      </dl>
    </section>
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
  const gallery = assets.filter((a) => !usedIds.has(a.id));
  return (
    <article className="wrap">
      <Opening bundle={bundle} />
      <Glance bundle={bundle} />

      {narrative.summary && narrative.summary.length > 0 && (
        <section className="project-section project-section--lead" aria-label="In brief">
          <div className="grid-2">
            <div className="project-section__head"><p className="tag">In brief</p></div>
            <div className="prose">{narrative.summary.map((p, i) => <p key={i} className={i === 0 ? "statement statement--small" : undefined}>{p}</p>)}</div>
          </div>
        </section>
      )}
      <section className="project-section" aria-labelledby="challenge">
        <div className="grid-2">
          <div className="project-section__head"><p className="tag">Context</p><h2 id="challenge" className="section__title">The challenge</h2></div>
          <div className="prose">
            {narrative.challenge.map((p, i) => <p key={i}>{p}</p>)}
            <ClaimList claims={getClaims(bundle, "context")} />
          </div>
        </div>
      </section>

      <section className="project-section" aria-labelledby="vision">
        <div className="grid-2">
          <div className="project-section__head"><p className="tag">Insight and vision</p><h2 id="vision" className="section__title">The idea that guided the team</h2></div>
          <div className="prose">
            {narrative.insight.map((p, i) => <p key={`i-${i}`} className="statement">{p}</p>)}
            {narrative.vision.map((p, i) => <p key={`v-${i}`}>{p}</p>)}
          </div>
        </div>
      </section>

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

      <section className="project-section" aria-labelledby="leadership">
        <div className="grid-2">
          <div className="project-section__head"><p className="tag">Leadership and collaboration</p><h2 id="leadership" className="section__title">What was led, and by whom</h2></div>
          <div className="prose">
            {narrative.leadership.map((p, i) => <p key={i}>{p}</p>)}
            {narrative.leadershipMoment && (<><p className="tag">A moment of alignment</p><p>{narrative.leadershipMoment}</p></>)}
            <ClaimList claims={getClaims(bundle, "leadership")} />
          </div>
        </div>
      </section>

      <section className="project-section" aria-labelledby="outcome">
        <div className="grid-2">
          <div className="project-section__head"><p className="tag">Outcome and reflection</p><h2 id="outcome" className="section__title">What was delivered</h2></div>
          <div className="prose">
            {narrative.outcome.map((p, i) => <p key={i}>{p}</p>)}
            <ClaimList claims={getClaims(bundle, "outcome")} />
            {narrative.reflection && (<><p className="tag">Reflection</p><p className="statement statement--small">{narrative.reflection}</p></>)}
          </div>
        </div>
      </section>

      <Gallery assets={gallery} title="Additional material" />
      <Credits bundle={bundle} />
      <Related bundle={bundle} />
    </article>
  );
}

function LightTemplate({ bundle }: { bundle: ProjectBundle }) {
  const { project, narrative } = bundle;
  const assets = visibleAssets(bundle).filter((a) => a.id !== project.heroAssetId && !bundle.decisions.some((d) => d.assetIds.includes(a.id)));
  return (
    <article className="wrap">
      <Opening bundle={bundle} />
      <Glance bundle={bundle} />
      <section className="project-section" aria-labelledby="story">
        <div className="grid-2">
          <div className="project-section__head"><p className="tag">The work</p><h2 id="story" className="section__title">Context, idea, and what was made</h2></div>
          <div className="prose">
            {(narrative.summary ?? []).map((p, i) => <p key={i}>{p}</p>)}
            <ClaimList claims={getClaims(bundle, "context")} />
            <ClaimList claims={getClaims(bundle, "leadership")} />
            <ClaimList claims={getClaims(bundle, "outcome")} />
          </div>
        </div>
      </section>
      {bundle.decisions.length > 0 && <DecisionBlocks bundle={{ ...bundle, decisions: bundle.decisions.slice(0, 1) }} />}
      <Gallery assets={assets} title="Views" />
      <Credits bundle={bundle} />
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
