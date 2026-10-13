import type { Metadata } from "next";
import { getCoreProjects, getExtendedProjects, getLensCounts } from "@/lib/content";
import WorkCard from "@/components/WorkCard";
import Parallax from "@/components/Parallax";
import { LensProvider, LensKey } from "@/components/LensContext";

export const metadata: Metadata = {
  title: "Work",
  description: "An ordered sequence of projects showing one creative direction carried across culture, place, behavior, and detail.",
};

export default function WorkPage() {
  const core = getCoreProjects();
  const extended = getExtendedProjects();
  const counts = getLensCounts();
  return (
    <div className="wrap">
      <section className="page-head" aria-labelledby="work-title">
        <p className="tag">Work</p>
        <h1 id="work-title" className="page-head__title">One direction, read at every scale</h1>
        <p className="lede">
          The common thread is a shared idea, established early and tested in detail. The sequence opens with the strongest combined evidence of vision and leadership, changes scale to show range, deepens into human experience and execution, and closes with the kind of contribution a next employer could expect.
        </p>
      </section>
      <LensProvider>
        <div className="lens-filter" aria-label="Highlight by lens">
          <p className="tag">Highlight by lens. The order never changes.</p>
          <LensKey counts={counts} compact />
        </div>
        {core.length ? (
          <div className="work-index">
            {core.map((bundle, index) => <WorkCard key={bundle.project.id} bundle={bundle} index={index} />)}
          </div>
        ) : (
          <p className="empty-state">
            No projects are cleared for publication yet. Set a project&apos;s permission to confirmed in its content file, or build with NEXT_PUBLIC_SHOW_DRAFTS=true to preview drafts.
          </p>
        )}
        {extended.length > 0 && (
          <section className="more-work" aria-labelledby="more-work">
            <h2 id="more-work" className="section__title">More work</h2>
            <div className="more-work__grid">
              {extended.map((bundle, index) => <WorkCard key={bundle.project.id} bundle={bundle} index={index} variant="small" />)}
            </div>
          </section>
        )}
      </LensProvider>
      <Parallax />
    </div>
  );
}
