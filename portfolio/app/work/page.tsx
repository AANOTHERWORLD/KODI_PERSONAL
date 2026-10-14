import type { Metadata } from "next";
import { getWorkGroups, getHeroAsset, getLensCounts } from "@/lib/content";
import Picture from "@/components/Picture";
import WorkTile from "@/components/WorkTile";
import { LensProvider, LensKey } from "@/components/LensContext";

export const metadata: Metadata = {
  title: "Work",
  description: "An ordered sequence of projects showing one creative direction carried across culture, place, behavior, and detail.",
};

export default function WorkPage() {
  // Core projects only: extended placeholders stay out of navigation until they have a story and assets.
  const { selected, further } = getWorkGroups();
  const core = [...selected, ...further];
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
          <h1 id="work-title" className="work-banner__title">Work</h1>
          <p className="work-banner__lede">I help teams carry a clear idea from concept into the places and experiences people encounter every day, across workplaces, shared amenities, retail environments and brand platforms.</p>
        </div>
      </section>
      <div className="wrap">
      <LensProvider>
        <div className="lens-filter" aria-label="Highlight by lens">
          <p className="tag">Explore by lens</p>
          <LensKey counts={counts} compact total={projects.length} />
        </div>
        {projects.length ? (
          <>
            <h2 className="work-group__title">Selected projects</h2>
            <ol className="work-grid" aria-label="Selected projects">
              {selected.map((bundle, index) => <WorkTile key={bundle.project.id} bundle={bundle} index={index} />)}
            </ol>
            {further.length > 0 && (
              <>
                <h2 className="work-group__title">Further work</h2>
                <ol className="work-grid" aria-label="Further work">
                  {further.map((bundle, index) => <WorkTile key={bundle.project.id} bundle={bundle} index={selected.length + index} />)}
                </ol>
              </>
            )}
          </>
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
