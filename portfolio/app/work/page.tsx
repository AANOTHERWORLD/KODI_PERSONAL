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
    <>
      <section className="work-banner" aria-labelledby="work-title" data-header-invert>
        {hero && (
          <div className="work-banner__media">
            <Picture asset={hero} showCaption={false} fit="cover" sizes="100vw" priority />
          </div>
        )}
        <div className="work-banner__scrim" aria-hidden="true" />
        <div className="work-banner__text wrap">
          <p className="tag">Work</p>
          <h1 id="work-title" className="work-banner__title">One direction, expressed at different scales</h1>
          <p className="work-banner__lede">Selected projects spanning places, experiences, and brand expression. Each begins with a clear idea and shows the decisions, collaboration, and details that carry it forward.</p>
        </div>
      </section>
      <div className="wrap">
      <LensProvider>
        <div className="lens-filter" aria-label="Highlight by lens">
          <p className="tag">Filter by lens</p>
          <LensKey counts={counts} compact total={projects.length} />
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
    </>
  );
}
