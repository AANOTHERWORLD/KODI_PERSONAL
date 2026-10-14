import type { Metadata } from "next";
import { portfolio, profile, getProfileClaimsById, getProfileAsset } from "@/lib/content";
import { getDownloads } from "@/lib/files";
import { withBasePath } from "@/lib/basePath";
import Picture from "@/components/Picture";

export const metadata: Metadata = {
  title: "About",
  description: "Biography, career narrative, experience, recognition, and leadership scope.",
};

function ClaimRows({ ids }: { ids: string[] }) {
  const claims = getProfileClaimsById(ids);
  if (!claims.length) return <p className="tag">Awaiting confirmed items.</p>;
  return (
    <ul className="ruled-list">
      {claims.map((claim) => (
        <li key={claim.id} className={claim.status === "awaiting" ? "claim--awaiting" : undefined}>
          {claim.wording}
          {claim.status === "awaiting" && <> <span className="draft-marker">Awaiting verification</span></>}
        </li>
      ))}
    </ul>
  );
}

export default function AboutPage() {
  const downloads = getDownloads();
  const portrait = getProfileAsset(profile.portraitAssetId);
  return (
    <div className="wrap">
      <section className="page-head" aria-labelledby="about-title">
        <p className="tag">About</p>
        <h1 id="about-title" className="page-head__title">{portfolio.name}</h1>
        <p className="lede">{profile.currentTitle}. {profile.bio}</p>
      </section>

      {portrait && <div className="about-portrait"><Picture asset={portrait} fit="cover" sizes="(min-width: 1100px) 1100px, 100vw" /></div>}

      <section className="section" aria-labelledby="career">
        <div className="grid-2">
          <div><p className="tag">Career narrative</p><h2 id="career" className="section__title">How multidisciplinary experience shapes judgment</h2></div>
          <div className="prose">{profile.careerNarrative.map((p, i) => <p key={i}>{p}</p>)}</div>
        </div>
      </section>

      <section className="section" aria-labelledby="experience">
        <div className="grid-2">
          <div><p className="tag">Experience</p><h2 id="experience" className="section__title">Timeline</h2></div>
          <ol className="timeline timeline--ink">
            {profile.experience.map((item) => (
              <li key={`${item.title}-${item.years}`} className="timeline__row"><span>{item.title}</span><span>{item.practice}</span><span>{item.years}</span></li>
            ))}
          </ol>
        </div>
      </section>

      <section className="section" aria-labelledby="recognition">
        <div className="grid-2">
          <div><p className="tag">Recognition</p><h2 id="recognition" className="section__title">Highlights</h2></div>
          <div><ClaimRows ids={profile.recognitionClaimIds} /></div>
        </div>
      </section>

      <section className="section" aria-labelledby="leadership">
        <div className="grid-2">
          <div><p className="tag">Leadership scope and working style</p><h2 id="leadership" className="section__title">Verified claims only</h2></div>
          <div className="prose">
            <ul>{profile.workingStyle.map((s) => <li key={s}>{s}</li>)}</ul>
            <ClaimRows ids={profile.leadershipClaimIds} />
          </div>
        </div>
      </section>

      <section className="section" aria-labelledby="credentials">
        <div className="grid-2">
          <div><p className="tag">Credentials</p><h2 id="credentials" className="section__title">Selected credentials</h2></div>
          <div>
            <ul>{profile.credentials.map((c) => <li key={c}>{c}</li>)}</ul>
            <div className="actions">
              {downloads.portfolioPdf && <a href={withBasePath(downloads.portfolioPdf)} className="button" data-sweep>Portfolio PDF</a>}
              {downloads.cvPdf && <a href={withBasePath(downloads.cvPdf)} className="button" data-sweep>CV</a>}
            </div>
            <p className="tag" style={{ marginTop: "var(--space-3)" }}>{portfolio.location}. {portfolio.availability}</p>
          </div>
        </div>
      </section>
    </div>
  );
}
