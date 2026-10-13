import Link from "next/link";
import type { ProjectBundle } from "@/content/types";
import { getIndexAsset } from "@/lib/content";
import Picture from "./Picture";
import LensTags from "./LensTags";

export const MIN_TILE_PX = 220;
export const MAX_TILE_PX = 620;

export function tileHeight(size: 1 | 2 | 3 | 4): number {
  return Math.round(MIN_TILE_PX + ((MAX_TILE_PX - MIN_TILE_PX) * (size - 1)) / 3);
}

const STATUS_LABEL = { completed: "Completed", "in-progress": "In progress", concept: "Concept" } as const;

type Props = { bundle: ProjectBundle; index: number; compact?: boolean };

// A clickable link block: link > media wrapper > img, so the hover zoom targets the real image.
export default function WorkEntry({ bundle, index, compact = false }: Props) {
  const { project } = bundle;
  const asset = getIndexAsset(bundle);
  const side = index % 2 === 0 ? "left" : "right";
  const height = tileHeight(project.tileSize);
  return (
    <article className={`work-entry work-entry--${side} work-entry--size-${project.tileSize} ${compact ? "work-entry--compact" : ""}`}>
      <Link href={`/work/${project.slug}/`} className="work-entry__link" data-cursor="ring">
        <div className="work-entry__media" data-parallax style={{ "--tile-height": `${height}px` } as React.CSSProperties}>
          {asset ? <Picture asset={asset} showCaption={false} fit="cover" sizes="(min-width: 900px) 70vw, 100vw" priority={index === 0} /> : <div className="picture__placeholder">Image pending</div>}
        </div>
        <div className="work-entry__text">
          <p className="work-entry__kicker">
            <span className="work-entry__number">{String(project.sequence).padStart(2, "0")}</span>
            <span className="work-entry__role">{project.portfolioRole}</span>
            {project.status !== "completed" && <span className="status-label">{STATUS_LABEL[project.status]}</span>}
            {project.permission === "pending" && <span className="draft-marker">Draft: permission pending</span>}
          </p>
          <h3 className="work-entry__title">{project.title}</h3>
          <p className="work-entry__thesis">{project.thesis}</p>
          <p className="work-entry__meta">{project.role}</p>
        </div>
      </Link>
      <LensTags lenses={project.lenses} className="work-entry__lenses" />
    </article>
  );
}
