import type { Metadata } from "next";
import Link from "next/link";
import { portfolio, profile, getProfileClaimsById, getProfileAsset } from "@/lib/content";
import { getDownloads } from "@/lib/files";
import { withBasePath } from "@/lib/basePath";
import Picture from "@/components/Picture";

export const metadata: Metadata = {
  title: "About",
  description: "A multidisciplinary design leader working across architecture, interiors, brand, and experience, with the scope of current leadership.",
};

export default function AboutPage() {
  const downloads = getDownloads();
  const portrait = getProfileAsset(profile.portraitAssetId);
  const recognition = getProfileClaimsById(profile.recognitionClaimIds);
  const mailto = `mailto:${portfolio.email}?subject=${encodeURIComponent(portfolio.emailSubject)}`;
  const [lead, ...rest] = profile.aboutIntro;
  return (
    <div className="wrap">
      <section className="page-head" aria-labelledby="about-title">
        <p className="tag">About</p>
        <h1 id="about-title" className="page-head__title page-head__title--sentence">{lead}</h1>
      </section>

      <section className="about-intro" aria-label="Introduction">
        {portrait && <div className="about-intro__portrait"><Picture asset={portrait} fit="cover" sizes="(min-width: 900px) 40vw, 100vw" /></div>}
        <div className="about-intro__text prose">
          {rest.map((p, i) => <p key={i}>{p}</p>)}
        </div>
      </section>

      <section className="section about-snapshot" aria-labelledby="snapshot">
        <p className="tag">Leadership snapshot</p>
        <h2 id="snapshot" className="visually-hidden">Leadership snapshot</h2>
        <ul className="snapshot-list">
          {profile.leadershipSnapshot.map((item) => <li key={item}>{item}</li>)}
        </ul>
      </section>

      <section className="section" aria-labelledby="experience">
        <div className="grid-2">
          <div><p className="tag">Experience</p><h2 id="experience" className="section__title">Current role, past roles, and next focus</h2></div>
          <div>
            <ol className="timeline timeline--ink">
              {profile.experience.map((item, i) => (
                <li key={`${item.title}-${item.years}`} className="timeline__row">
                  <span>{item.title}{i === 0 && <span className="tag tag--status">Current</span>}</span><span>{item.practice}</span><span>{item.years}</span>
                </li>
              ))}
              <li className="timeline__row timeline__row--next"><span>Next focus</span><span>Creative Director, multidisciplinary design practice</span><span>Seeking</span></li>
            </ol>
          </div>
        </div>
      </section>

      <section className="section" aria-labelledby="leadership">
        <div className="grid-2">
          <div><p className="tag">Leadership</p><h2 id="leadership" className="section__title">{profile.leadershipStatement}</h2></div>
          <div className="prose">
            <p>{profile.leadershipSummary}</p>
            {profile.leadershipNarrative.map((p, i) => <p key={i}>{p}</p>)}
            <ul>{profile.workingStyle.map((s) => <li key={s}>{s}</li>)}</ul>
          </div>
        </div>
      </section>

      {recognition.length > 0 && (
        <section className="section" aria-labelledby="recognition">
          <div className="grid-2">
            <div><p className="tag">Recognition</p><h2 id="recognition" className="section__title">Selected project recognition</h2></div>
            <ul className="ruled-list">
              {recognition.map((claim) => <li key={claim.id}>{claim.url ? <a href={claim.url} rel="noopener" data-sweep className="sweep-link">{claim.wording}</a> : claim.wording}</li>)}
            </ul>
          </div>
        </section>
      )}

      {profile.credentials.length > 0 && (
        <section className="section" aria-labelledby="credentials">
          <div className="grid-2">
            <div><p className="tag">Credentials</p><h2 id="credentials" className="section__title">Selected credentials</h2></div>
            <ul>{profile.credentials.map((c) => <li key={c}>{c}</li>)}</ul>
          </div>
        </section>
      )}

      <section className="section" aria-labelledby="availability">
        <div className="grid-2">
          <div><p className="tag">Contact</p><h2 id="availability" className="section__title">Open to Creative Director roles</h2></div>
          <div className="prose">
            <p>{portfolio.internationalAvailability}</p>
            <div className="actions">
              <a href={mailto} className="button button--accent" data-sweep>Get in touch</a>
              {downloads.portfolioPdf && <a href={withBasePath(downloads.portfolioPdf)} className="button" data-sweep>Download selected work</a>}
              {downloads.cvPdf && <a href={withBasePath(downloads.cvPdf)} className="button" data-sweep>CV</a>}
              <Link href="/work/" className="text-link" data-sweep>Explore selected work</Link>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
