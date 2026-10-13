import type { LensId } from "@/content/types";
import { lensById } from "@/content/lenses";

export default function LensTags({ lenses, className }: { lenses: LensId[]; className?: string }) {
  return (
    <ul className={`lens-tags ${className ?? ""}`} aria-label="Lenses">
      {lenses.map((id) => (
        <li key={id} className="lens-tag" data-lens={id}>
          <span className="lens-tag__numeral" aria-hidden="true">{lensById[id].numeral}</span>
          {lensById[id].name}
        </li>
      ))}
    </ul>
  );
}
