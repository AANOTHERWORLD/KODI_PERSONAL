import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { PLACEHOLDER_SLUG, getAllProjectSlugs, getProject, getProjectById, getAsset, getHeroAsset, getIndexAsset, getClaims, visibleAssets, lensById } from "@/lib/content";
import Picture from "@/components/Picture";
import LensTags from "@/components/LensTags";
import DraftBadge from "@/components/DraftBadge";
import type { Claim } from "@/content/types";

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

const STATUS_LABEL = { completed: "Completed", "in-progress": "In progress", concept: "Concept" } as const;

function ClaimList({ claims }: { claims: Claim[] }) {
  if (!claims.length) return null;
  return (
    <ul className="claims" style={{ listStyle: "none", padding: 0, display: "grid", gap: "0.8rem" }}>
      {claims.map((claim) => (
        <li key={claim.id} className={claim.status === "awaiting" ? "claim--awaiting" : undefined}>
          {claim.wording}
          {claim.status === "awaiting" && <> <span className="draft-marker">Awaiting verification</span></>}
        </li>
      ))}
    </ul>
  );
}

export default async function ProjectPage({ params }: Props) {
  const { slug } = await params;
  const bundle = getProject(slug);
  if (!bundle && slug === PLACEHOLDER_SLUG) {
    return (
      <div className="wrap">
        <section className="hero">
          <p className="kicker">Selected work</p>
          <h1 className="hero__headline">Case studies are being cleared for publication</h1>
          <p className="hero__positioning">Project pages appear here once client and studio permission is confirmed. In the meantime, the approach and contact pages are open.</p>
          <div className="hero__actions">
            <Link href="/approach/" className="button" data-cursor="ring">Read the approach</Link>
            <Link href="/contact/" className="text-link">Get in touch</Link>
          </div>
        </section>
      </div>
    );
  }
  if (!bundle) notFound();
  const { project, narrative, decisions } = bundle;
  const hero = getHeroAsset(bundle);
  const related = getProjectById(project.relatedProject);
  const relatedAsset = related ? getIndexAsset(related) : null;
  const assets = visibleAssets(bundle);
  const usedIds = new Set<string>([project.heroAssetId, ...decisions.flatMap((d) => d.assetIds), ...narrative.scaleTranslation.map((s) => s.assetId).filter(Boolean) as string[]]);
  const gallery = assets.filter((a) => !usedIds.has(a.id));

  return (
    <article className="wrap">
      {/* 1. Opening */}
      <header className="project-hero">
        <p className="kicker">
          {String(project.sequence).padStart(2, "0")} {project.portfolioRole}
          {project.status !== "completed" && <> <span className="status-label">{STATUS_LABEL[project.status]}</span></>}
        </p>
        {project.permission === "pending" && <DraftBadge note={project.permissionNote} />}
        <h1 className="project-hero__title">{project.title}</h1>
        <p className="project-hero__thesis">{project.thesis}</p>
        <div className="project-hero__media">
          {hero ? <Picture asset={hero} priority sizes="(min-width: 1280px) 1280px, 100vw" showLens /> : <div className="picture__placeholder">Hero image pending</div>}
        </div>
      </header>

      {/* 2. At a glance */}
      <dl className="glance" aria-label="At a glance">
        <div className="glance__item"><dt>Client</dt><dd>{project.clientDisplayName}</dd></div>
        <div className="glance__item"><dt>Location</dt><dd>{project.location}</dd></div>
        <div className="glance__item"><dt>Years</dt><dd>{project.years}</dd></div>
        <div className="glance__item"><dt>Status</dt><dd>{STATUS_LABEL[project.status]}{project.statusNote ? `. ${project.statusNote}` : ""}</dd></div>
        <div className="glance__item glance__item--wide"><dt>Role</dt><dd>{project.role}<ClaimList claims={getClaims(bundle, "role")} /></dd></div>
        <div className="glance__item glance__item--wide"><dt>Scope</dt><dd>{project.scope}</dd></div>
        <div className="glance__item"><dt>Practice</dt><dd>{project.practice}</dd></div>
        <div className="glance__item"><dt>Team</dt><dd>{project.team.join(", ")}</dd></div>
        <div className="glance__item"><dt>Collaborators</dt><dd>{project.collaborators.length ? project.collaborators.join("; ") : "See credits"}</dd></div>
        <div className="glance__item"><dt>Lenses</dt><dd><LensTags lenses={project.lenses} /></dd></div>
      </dl>

      {/* 3. Context and challenge */}
      <section className="project-section" aria-labelledby="challenge">
        <div className="grid-2">
          <div className="project-section__head"><p className="kicker">Context</p><h2 id="challenge" className="project-section__title">The challenge</h2></div>
          <div className="prose">
            {narrative.challenge.map((p, i) => <p key={i}>{p}</p>)}
            <ClaimList claims={getClaims(bundle, "context")} />
          </div>
        </div>
      </section>

      {/* 4. Insight and creative vision */}
      <section className="project-section" aria-labelledby="vision">
        <div className="grid-2">
          <div className="project-section__head"><p className="kicker">Insight and vision</p><h2 id="vision" className="project-section__title">The idea that guided the team</h2></div>
          <div className="prose">
            {narrative.insight.map((p, i) => <p key={`i-${i}`} className="vision-statement">{p}</p>)}
            {narrative.vision.map((p, i) => <p key={`v-${i}`}>{p}</p>)}
          </div>
        </div>
      </section>

      {/* 5. Decisive choices */}
      <section className="project-section" aria-labelledby="decisions">
        <div className="project-section__head"><p className="kicker">Decisive choices</p><h2 id="decisions" className="project-section__title">Three decisions that shaped the outcome</h2></div>
        {decisions.map((decision, index) => (
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

      {/* 6. Translation across scales */}
      <section className="project-section" aria-labelledby="scales">
        <div className="project-section__head"><p className="kicker">Translation across scales</p><h2 id="scales" className="project-section__title">How the idea changed form and stayed itself</h2></div>
        <div className="scale-sequence">
          {narrative.scaleTranslation.map((step, index) => {
            const asset = getAsset(bundle, step.assetId);
            return (
              <div className={`scale-step ${asset ? "" : "scale-step--text-only"}`} key={index}>
                {asset && <div className="scale-step__media"><Picture asset={asset} sizes="(min-width: 900px) 66vw, 100vw" /></div>}
                <div className="scale-step__text">
                  <p className="scale-step__lens"><span className="lens-tag"><span className="lens-tag__numeral" aria-hidden="true">{lensById[step.lens].numeral}</span>{lensById[step.lens].name}</span></p>
                  <p className="scale-step__caption">{step.caption}</p>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* 7. Leadership and collaboration */}
      <section className="project-section" aria-labelledby="leadership">
        <div className="grid-2">
          <div className="project-section__head"><p className="kicker">Leadership and collaboration</p><h2 id="leadership" className="project-section__title">What was led, and by whom</h2></div>
          <div className="prose">
            {narrative.leadership.map((p, i) => <p key={i}>{p}</p>)}
            {narrative.leadershipMoment && (
              <>
                <p className="kicker" style={{ marginTop: "var(--space-3)" }}>A moment of alignment</p>
                <p>{narrative.leadershipMoment}</p>
              </>
            )}
            <ClaimList claims={getClaims(bundle, "leadership")} />
          </div>
        </div>
      </section>

      {/* 8. Outcome and reflection */}
      <section className="project-section" aria-labelledby="outcome">
        <div className="grid-2">
          <div className="project-section__head"><p className="kicker">Outcome and reflection</p><h2 id="outcome" className="project-section__title">What was delivered</h2></div>
          <div className="prose">
            {narrative.outcome.map((p, i) => <p key={i}>{p}</p>)}
            <ClaimList claims={getClaims(bundle, "outcome")} />
            {narrative.reflection && (
              <>
                <p className="kicker" style={{ marginTop: "var(--space-3)" }}>Reflection</p>
                <p className="vision-statement" style={{ fontSize: "var(--step-1)" }}>{narrative.reflection}</p>
              </>
            )}
          </div>
        </div>
      </section>

      {gallery.length > 0 && (
        <section className="project-section" aria-labelledby="more">
          <div className="project-section__head"><p className="kicker">More views</p><h2 id="more" className="project-section__title">Additional material</h2></div>
          <div className="gallery">
            {gallery.map((asset) => <Picture key={asset.id} asset={asset} sizes="(min-width: 1100px) 1100px, 100vw" showLens />)}
          </div>
        </section>
      )}

      {/* 9. Credits */}
      <section className="project-section" aria-labelledby="credits">
        <div className="project-section__head"><p className="kicker">Credits</p><h2 id="credits" className="project-section__title">Who did what</h2></div>
        <dl className="credits">
          <div><dt>Originating practice</dt><dd>{project.practice}</dd></div>
          <div><dt>Personal involvement</dt><dd>{narrative.involvement}</dd></div>
          <div><dt>Team</dt><dd><ul>{project.team.map((t) => <li key={t}>{t}</li>)}</ul></dd></div>
          <div><dt>Collaborators</dt><dd>{project.collaborators.length ? <ul>{project.collaborators.map((c) => <li key={c}>{c}</li>)}</ul> : "To be confirmed"}</dd></div>
          <div><dt>Photography and imagery</dt><dd>{narrative.photographyCredit ?? narrative.imageCredit ?? "See captions"}{narrative.photographyCredit && narrative.imageCredit ? ` ${narrative.imageCredit}` : ""}</dd></div>
          <div><dt>Further credits</dt><dd><ClaimList claims={getClaims(bundle, "credits")} />{getClaims(bundle, "credits").length === 0 && "None pending"}</dd></div>
        </dl>
      </section>

      {/* 10. Related project */}
      {related && (
        <section className="related" aria-labelledby="related">
          <p className="kicker">Related project</p>
          <Link href={`/work/${related.project.slug}/`} className="related__link" data-cursor="ring">
            {relatedAsset && <Picture asset={relatedAsset} showCaption={false} fit="cover" sizes="(min-width: 800px) 45vw, 100vw" />}
            <div>
              <h2 id="related" className="related__title">{related.project.title}</h2>
              <p className="lede">{related.project.thesis}</p>
              <LensTags lenses={related.project.lenses} />
            </div>
          </Link>
        </section>
      )}
    </article>
  );
}
