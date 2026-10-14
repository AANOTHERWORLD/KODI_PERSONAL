import Link from "next/link";
import type { ProjectBundle } from "@/content/types";
import { getHeroAsset, getIndexAsset } from "@/lib/content";
import Picture from "./Picture";
import { LensAwareEntry } from "./LensContext";

// A cell in the Work grid: the project's hero image. On hover or focus the cell grows 5%
// above its neighbours, the image darkens and zooms slightly inside it, and the title, category
// and headline appear. The text is always in the markup for screen readers and search.
export default function WorkTile({ bundle, index }: { bundle: ProjectBundle; index: number }) {
  const { project } = bundle;
  const asset = getHeroAsset(bundle) ?? getIndexAsset(bundle);
  const category = project.typeLabel;
  return (
    <LensAwareEntry lensIds={project.lenses} as="li" className="work-tile" mode="filter">
      <Link href={`/work/${project.slug}/`} className="work-tile__link cursor-tile">
        <div className="work-tile__media">
          {asset ? <Picture asset={asset} showCaption={false} fit="cover" sizes="(min-width: 1100px) 25vw, (min-width: 720px) 50vw, 100vw" priority={index < 4} /> : <div className="picture__placeholder">Image pending</div>}
        </div>
        <div className="work-tile__text">
          <p className="work-tile__category tag">{category}</p>
          <h2 className="work-tile__title">{project.title}</h2>
          <p className="work-tile__headline">{project.thesis}</p>
          {project.permission === "pending" && <span className="draft-marker">Draft: permission pending</span>}
        </div>
      </Link>
    </LensAwareEntry>
  );
}
