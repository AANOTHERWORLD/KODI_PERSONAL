import type { LensId } from "@/content/types";
import { lensById } from "@/content/lenses";

export default function LensTags({ lenses, className, max }: { lenses: LensId[]; className?: string; max?: number }) {
  const list = max ? lenses.slice(0, max) : lenses;
  return (
    <ul className={`lens-tags ${className ?? ""}`} aria-label="Lenses">
      {list.map((id) => (
        <li key={id} className="tag tag--lens" data-lens={id}>
          {lensById[id].name}
        </li>
      ))}
    </ul>
  );
}
