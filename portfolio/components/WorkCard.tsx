import Link from "next/link";
import type { ProjectBundle } from "@/content/types";
import { getIndexAsset } from "@/lib/content";
import Picture from "./Picture";
import { LensAwareEntry } from "./LensContext";
import { lensById } from "@/content/lenses";
import type { LensId } from "@/content/types";

const LENS_SHORT = Object.fromEntries(Object.values(lensById).map((l) => [l.id, l.name])) as Record<LensId, string>;

export const MIN_TILE_PX = 220;
export const MAX_TILE_PX = 620;

export function tilePx(size: 1 | 2 | 3 | 4): number {
  return Math.round(MIN_TILE_PX + ((MAX_TILE_PX - MIN_TILE_PX) * (size - 1)) / 3);
}

export const STATUS_LABEL = { completed: "Completed", "in-progress": "In progress", concept: "Concept" } as const;

type Props = { bundle: ProjectBundle; index: number; variant?: "card" | "small" };

// A project card: link block > media (floating image with a soft shadow) beside its text.
// Even cards put the image left and the text right, odd cards the reverse, so the section
// reads as a field rather than a column. Everything shown is always visible.
export default function WorkCard({ bundle, index, variant = "card" }: Props) {
  const { project } = bundle;
  const asset = getIndexAsset(bundle);
  const side = index % 2 === 0 ? "left" : "right";
  return (
    <LensAwareEntry lensIds={project.lenses} as="article" className={`work-card work-card--${variant} work-card--${side} work-card--size-${project.tileSize}`} reveal>
      <Link href={`/work/${project.slug}/`} className="work-card__link">
        <div className="work-card__frame">
          <div className="work-card__media" data-parallax style={{ "--tile-height": `${tilePx(project.tileSize)}px` } as React.CSSProperties}>
            {asset ? <Picture asset={asset} showCaption={false} fit="cover" sizes="(min-width: 900px) 60vw, 100vw" priority={index === 0} /> : <div className="picture__placeholder">Image pending</div>}
          </div>
        </div>
        <div className="work-card__text">
          <h3 className="work-card__title">{project.title}</h3>
          <p className="work-card__thesis">{project.thesis}</p>
          <p className="work-card__meta tag">
            {project.typeLabel}
            {project.status !== "completed" && <span className="tag tag--status">{STATUS_LABEL[project.status]}</span>}
          </p>
          <p className="work-card__disciplines">{project.disciplines}</p>
          <p className="work-card__role tag">{project.role}</p>
        </div>
      </Link>
    </LensAwareEntry>
  );
}
