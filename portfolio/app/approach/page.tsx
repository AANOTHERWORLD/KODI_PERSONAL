import type { Metadata } from "next";
import Link from "next/link";
import { approachSteps, getApproachExamples, getProjectById, lenses } from "@/lib/content";
import { approachAi, approachHeading, approachIntro } from "@/content/approach";
import { lensHeading, lensIntro } from "@/content/lenses";

export const metadata: Metadata = {
  title: "Approach",
  description: "A recurring method: read the context, define the direction, connect the scales, guide the team, protect the intent.",
};

export default function ApproachPage() {
  return (
    <div className="wrap">
      <section className="page-head" aria-labelledby="approach-title">
        <p className="tag">Approach</p>
        <h1 id="approach-title" className="page-head__title">{approachHeading}</h1>
        <p className="lede">{approachIntro}</p>
      </section>

      <section className="section" aria-label="The five steps">
        <div className="steps">
          {approachSteps.map((step) => {
            const examples = getApproachExamples(step.id);
            return (
              <div className="step" key={step.id} id={step.id}>
                <div>
                  <p className="step__number">{String(step.number).padStart(2, "0")}</p>
                  <h2 className="step__title">{step.title}</h2>
                </div>
                <div>
                  <p>{step.summary}</p>
                  {examples.length > 0 && (
                    <ul className="step__examples">
                      {examples.map(({ example, project }) => (
                        <li key={`${step.id}-${project.project.id}`}>
                          {example.example}
                          <Link href={`/work/${project.project.slug}/`}>{project.project.title}</Link>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </section>

      <section className="section" aria-labelledby="ai-title">
        <div className="grid-2">
          <div><p className="tag">Tools</p><h2 id="ai-title" className="section__title">{approachAi.heading}</h2></div>
          <div className="prose">
            <p>{approachAi.body}</p>
            {getProjectById(approachAi.projectId) && (
              <p><Link href={`/work/${getProjectById(approachAi.projectId)!.project.slug}/`} className="text-link" data-sweep>See the Watt Plaza study</Link></p>
            )}
          </div>
        </div>
      </section>

      <section className="section" aria-labelledby="lenses-title">
        <p className="tag">The four lenses</p>
        <h2 id="lenses-title" className="section__title">{lensHeading}</h2>
        <p className="lede">{lensIntro}</p>
        <div className="lens-framework">
          {lenses.map((lens) => (
            <div className="lens-framework__item" key={lens.id}>
              <h3><span className="lens-key__dot" aria-hidden="true" />{lens.name}</h3>
              <p>{lens.role}</p>
              <p className="tag">{lens.question}</p>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
