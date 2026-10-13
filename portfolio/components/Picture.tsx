import type { Asset } from "@/content/types";
import { resolveImage } from "@/lib/images";
import { lensById } from "@/content/lenses";

type Props = {
  asset: Asset;
  sizes?: string;
  priority?: boolean;
  showCaption?: boolean;
  showLens?: boolean;
  className?: string;
  fit?: "contain" | "cover";
};

const TYPE_LABEL: Record<Asset["type"], string> = {
  photo: "Photograph",
  render: "Render",
  concept: "Concept",
  plan: "Plan",
  diagram: "Diagram",
  process: "Process",
};

// Server component. Emits a responsive <img> with srcset, sizes, explicit width and height
// (no layout shift), lazy loading below the fold, and a caption with type label and credit.
export default function Picture({ asset, sizes = "(min-width: 1100px) 1100px, 100vw", priority = false, showCaption = true, showLens = false, className, fit = "contain" }: Props) {
  const image = resolveImage(asset.file);
  if (!image) {
    return (
      <figure className={`picture picture--missing ${fit === "cover" ? "picture--cover" : ""} ${className ?? ""}`}>
        <div className="picture__placeholder" role="img" aria-label={asset.alt}>
          <span>Image to be supplied: {asset.file}</span>
        </div>
        {showCaption && <figcaption className="picture__caption"><span className="picture__text">{asset.caption}</span></figcaption>}
      </figure>
    );
  }
  const typeLabel = asset.projectId === "watt-plaza" && asset.type === "render" ? "AI-assisted concept render" : TYPE_LABEL[asset.type];
  return (
    <figure className={`picture ${fit === "cover" ? "picture--cover" : ""} ${image.vector ? "picture--vector" : ""} ${className ?? ""}`}>
      <div className="picture__media" style={fit === "cover" ? { aspectRatio: `${image.width} / ${image.height}` } : undefined}>
        <img
          src={image.src}
          srcSet={image.srcSet}
          sizes={image.srcSet ? sizes : undefined}
          width={image.width}
          height={image.height}
          alt={asset.alt}
          loading={priority ? "eager" : "lazy"}
          decoding={priority ? "sync" : "async"}
          fetchPriority={priority ? "high" : undefined}
        />
      </div>
      {showCaption && (
        <figcaption className="picture__caption">
          {showLens && asset.lens && <span className="tag tag--lens">{lensById[asset.lens].name}</span>}
          <span className="tag">{typeLabel}</span>
          <span className="picture__text">{asset.caption}</span>
          {asset.credit && <span className="picture__credit">{asset.credit}</span>}
          {asset.permission === "pending" && <span className="draft-marker">Draft: permission pending</span>}
        </figcaption>
      )}
    </figure>
  );
}
