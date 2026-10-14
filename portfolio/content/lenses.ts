import type { Lens, LensId } from "./types";

export const lenses: Lens[] = [
  {
    id: "culture-strategy",
    numeral: "I",
    name: "Culture & Strategy",
    short: "Culture",
    question: "What context, audience, or ambition gives the work meaning?",
    role: "Define the purpose, audience, and ambition.",
  },
  {
    id: "architecture-place",
    numeral: "II",
    name: "Architecture & Place",
    short: "Place",
    question: "How does the idea shape a setting and its relationship to its surroundings?",
    role: "Connect the idea to its setting.",
  },
  {
    id: "interiors-behavior",
    numeral: "III",
    name: "Interiors & Experience",
    short: "Experience",
    question: "How does the environment influence what people do and feel?",
    role: "Design for how people meet, move, work, and feel.",
  },
  {
    id: "brand-detail",
    numeral: "IV",
    name: "Brand & Expression",
    short: "Expression",
    question: "How does identity become recognizable in lived experience?",
    role: "Make the idea recognizable in everyday encounters.",
  },
];

export const lensById: Record<LensId, Lens> = Object.fromEntries(lenses.map((l) => [l.id, l])) as Record<
  LensId,
  Lens
>;

export const lensHeading = "Designing across disciplines";

export const lensIntro =
  "I bring culture, place, interiors and detail into the same design conversation, connecting what an organization stands for with how people experience it. Each perspective informs the others as the work develops, from the overall concept to the smallest detail.";
