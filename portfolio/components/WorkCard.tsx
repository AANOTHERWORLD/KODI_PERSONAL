import Link from "next/link";
import type { ProjectBundle } from "@/content/types";
import { getIndexAsset } from "@/lib/content";
import Picture from "./Picture";
import LensTags from "./LensTags";
import { LensAwareEntry } from "./LensContext";

export const MIN_TILE_PX = 220;
export const MAX_TILE_PX = 620;

export function tilePx(size: 1 | 2 | 3 | 4): number {
  return Math.round(MIN_TILE_PX + ((MAX_TILE_PX - MIN_TILE_PX) * (size - 1)) / 3);
}

export const STATUS_LABEL = { completed: "Completed", "in-progress": "In progress", concept: "Concept" } as const;

type Props = { bundle: ProjectBundle; index: number; variant?: "card" | "small" };

// A framed project card: link block > media wrapper > img, so hover zoom targets the image.
// The frame is a thin rule inset from the image. Everything shown is always visible.
export default function WorkCard({ bundle, index, variant = "card" }: Props) {
  const { project } = bundle;
  const asset = getIndexAsset(bundle);
  const side = index % 2 === 0 ? "left" : "right";
  return (
    <LensAwareEntry lensIds={project.lenses} as="article" className={`work-card work-card--${variant} work-card--${side} work-card--size-${project.tileSize}`}>
      <Link href={`/work/${project.slug}/`} className="work-card__link" data-cursor="ring">
        <div className="work-card__frame">
          <div className="work-card__media" data-parallax style={{ "--tile-height": `${tilePx(project.tileSize)}px` } as React.CSSProperties}>
            {asset ? <Picture asset={asset} showCaption={false} fit="cover" sizes="(min-width: 900px) 60vw, 100vw" priority={index === 0} /> : <div className="picture__placeholder">Image pending</div>}
          </div>
        </div>
        <div className="work-card__text">
          <p className="work-card__kicker">
            <span className="tag">{String(project.sequence).padStart(2, "0")} {project.portfolioRole}</span>
            {project.status !== "completed" && <span className="tag tag--status">{STATUS_LABEL[project.status]}</span>}
            {project.permission === "pending" && <span className="draft-marker">Draft: permission pending</span>}
          </p>
          <h3 className="work-card__title">{project.title}</h3>
          <p className="work-card__thesis">{project.thesis}</p>
          <p className="work-card__role tag">{project.role}</p>
        </div>
      </Link>
      <LensTags lenses={project.lenses} className="work-card__lenses" />
    </LensAwareEntry>
  );
}
