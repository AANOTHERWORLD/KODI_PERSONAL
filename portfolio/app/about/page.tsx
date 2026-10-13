import type { Metadata } from "next";
import { portfolio, profile, getProfileClaims } from "@/lib/content";
import { getDownloads } from "@/lib/files";
import { withBasePath } from "@/lib/basePath";

export const metadata: Metadata = {
  title: "About",
  description: "Biography, career narrative, leadership scope, and experience.",
};

export default function AboutPage() {
  const downloads = getDownloads();
  const leadership = getProfileClaims("profile-leadership");
  return (
    <div className="wrap">
      <section className="hero" aria-labelledby="about-title">
        <p className="kicker">About</p>
        <h1 id="about-title" className="hero__headline">{portfolio.name}</h1>
        <p className="hero__positioning">{profile.currentTitle}. {portfolio.availability}</p>
      </section>

      <section className="section" aria-labelledby="bio">
        <div className="grid-2">
          <div><p className="kicker">Biography</p><h2 id="bio">Current role</h2></div>
          <div className="prose">{profile.bio.map((p, i) => <p key={i}>{p}</p>)}</div>
        </div>
      </section>

      <section className="section" aria-labelledby="career">
        <div className="grid-2">
          <div><p className="kicker">Career narrative</p><h2 id="career">How multidisciplinary experience shapes judgment</h2></div>
          <div className="prose">{profile.careerNarrative.map((p, i) => <p key={i}>{p}</p>)}</div>
        </div>
      </section>

      <section className="section" aria-labelledby="leadership">
        <div className="grid-2">
          <div><p className="kicker">Leadership scope and working style</p><h2 id="leadership">Verified claims only</h2></div>
          <div className="prose">
            <ul>{profile.workingStyle.map((s) => <li key={s}>{s}</li>)}</ul>
            {leadership.length > 0 && (
              <ul style={{ listStyle: "none", padding: 0, display: "grid", gap: "0.8rem", marginTop: "var(--space-3)" }}>
                {leadership.map((claim) => (
                  <li key={claim.id} className={claim.status === "awaiting" ? "claim--awaiting" : undefined}>
                    {claim.wording}
                    {claim.status === "awaiting" && <> <span className="draft-marker">Awaiting verification</span></>}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      </section>

      <section className="section" aria-labelledby="experience">
        <div className="grid-2">
          <div><p className="kicker">Selected experience and credentials</p><h2 id="experience">Experience</h2></div>
          <div>
            <dl className="experience">
              {profile.experience.map((item, i) => (
                <div className="experience__item" key={i}>
                  <dt>{item.period}</dt>
                  <dd>
                    <strong>{item.title}</strong>, {item.organisation}
                    {item.note && <><br />{item.note}</>}
                  </dd>
                </div>
              ))}
            </dl>
            <p className="kicker" style={{ marginTop: "var(--space-4)" }}>Credentials</p>
            <ul>{profile.credentials.map((c) => <li key={c}>{c}</li>)}</ul>
            <div className="hero__actions">
              {downloads.portfolioPdf && <a href={withBasePath(downloads.portfolioPdf)} className="button" data-cursor="ring">Portfolio PDF</a>}
              {downloads.cvPdf && <a href={withBasePath(downloads.cvPdf)} className="button" data-cursor="ring">CV</a>}
            </div>
            <p style={{ marginTop: "var(--space-3)" }} className="site-footer__location">{portfolio.location}</p>
          </div>
        </div>
      </section>
    </div>
  );
}
