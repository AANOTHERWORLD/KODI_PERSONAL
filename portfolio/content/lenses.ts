import type { Lens, LensId } from "./types";

export const lenses: Lens[] = [
  {
    id: "culture-strategy",
    numeral: "I",
    name: "Culture / Strategy",
    short: "Culture",
    question: "What context, audience, or ambition gives the work meaning?",
  },
  {
    id: "architecture-place",
    numeral: "II",
    name: "Architecture / Place",
    short: "Place",
    question: "How does the idea shape a setting and its relationship to its surroundings?",
  },
  {
    id: "interiors-behavior",
    numeral: "III",
    name: "Interiors / Behavior",
    short: "Behavior",
    question: "How does the environment influence what people do and feel?",
  },
  {
    id: "brand-detail",
    numeral: "IV",
    name: "Brand / Detail",
    short: "Detail",
    question: "How does identity become recognizable in lived experience?",
  },
];

export const lensById: Record<LensId, Lens> = Object.fromEntries(lenses.map((l) => [l.id, l])) as Record<
  LensId,
  Lens
>;

export const lensIntro =
  "Scale means physical size, reach of influence, and the distance between strategic intent and individual experience. The four lenses interpret the work. Influence runs both ways: a detail can change the strategy, and a strategy can decide a detail.";
