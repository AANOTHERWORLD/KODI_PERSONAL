import type { Metadata } from "next";
import { getProjects } from "@/lib/content";
import WorkEntry from "@/components/WorkEntry";
import Parallax from "@/components/Parallax";

export const metadata: Metadata = {
  title: "Selected Work",
  description: "An ordered sequence of projects showing one creative direction carried across culture, place, behavior, and detail.",
};

export default function WorkPage() {
  const projects = getProjects();
  return (
    <div className="wrap">
      <section className="hero" aria-labelledby="work-title">
        <p className="kicker">Selected work</p>
        <h1 id="work-title" className="hero__headline">One direction, read at every scale</h1>
        <p className="hero__positioning">
          The common thread is a shared idea, established early and tested in detail. The sequence opens with the strongest combined evidence of vision and leadership, changes scale to show range, deepens into human experience and execution, and closes with the kind of contribution a next team could expect.
        </p>
      </section>
      {projects.length ? (
        <div className="work-index">
          {projects.map((bundle, index) => (
            <WorkEntry key={bundle.project.id} bundle={bundle} index={index} />
          ))}
        </div>
      ) : (
        <p className="empty-state">
          No projects are cleared for publication yet. Set a project&apos;s permission to confirmed in its content file, or build with NEXT_PUBLIC_SHOW_DRAFTS=true to preview drafts.
        </p>
      )}
      <Parallax />
    </div>
  );
}
