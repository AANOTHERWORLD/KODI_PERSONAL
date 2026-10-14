import type { Metadata } from "next";
import { getCoreProjects, getHeroAsset, getLensCounts } from "@/lib/content";
import Picture from "@/components/Picture";
import WorkTile from "@/components/WorkTile";
import { LensProvider, LensKey } from "@/components/LensContext";

export const metadata: Metadata = {
  title: "Work",
  description: "An ordered sequence of projects showing one creative direction carried across culture, place, behavior, and detail.",
};

export default function WorkPage() {
  // Core projects only: extended placeholders stay out of navigation until they have a story and assets.
  const core = getCoreProjects();
  const projects = core;
  const counts = getLensCounts();
  const hero = core.length ? getHeroAsset(core[0]) : null;
  return (
    <div className="wrap">
      <section className="page-head" aria-labelledby="work-title">
        <p className="tag">Work</p>
        <h1 id="work-title" className="page-head__title">One direction, expressed at different scales</h1>
        <p className="lede">Selected projects spanning places, experiences, and brand expression. Each begins with a clear idea and shows the decisions, collaboration, and details that carry it forward.</p>
      </section>
      {hero && (
        <div className="work-hero" data-reveal>
          <Picture asset={hero} showCaption={false} fit="cover" sizes="100vw" priority />
        </div>
      )}
      <LensProvider>
        <div className="lens-filter" aria-label="Highlight by lens">
          <p className="tag">Highlight by lens. The order never changes.</p>
          <LensKey counts={counts} compact />
        </div>
        {projects.length ? (
          <ol className="work-grid" aria-label="Projects">
            {projects.map((bundle, index) => <WorkTile key={bundle.project.id} bundle={bundle} index={index} />)}
          </ol>
        ) : (
          <p className="empty-state">
            No projects are cleared for publication yet. Set a project&apos;s permission to confirmed in its content file, or build with NEXT_PUBLIC_SHOW_DRAFTS=true to preview drafts.
          </p>
        )}
      </LensProvider>
    </div>
  );
}
