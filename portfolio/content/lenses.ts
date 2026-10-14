import type { Lens, LensId } from "./types";

export const lenses: Lens[] = [
  {
    id: "culture-strategy",
    numeral: "I",
    name: "Culture / Strategy",
    short: "Culture",
    question: "What context, audience, or ambition gives the work meaning?",
    role: "Define the purpose, audience, and ambition.",
  },
  {
    id: "architecture-place",
    numeral: "II",
    name: "Architecture / Place",
    short: "Place",
    question: "How does the idea shape a setting and its relationship to its surroundings?",
    role: "Connect the idea to its setting.",
  },
  {
    id: "interiors-behavior",
    numeral: "III",
    name: "Interiors / Behavior",
    short: "Behavior",
    question: "How does the environment influence what people do and feel?",
    role: "Design for how people meet, move, work, and feel.",
  },
  {
    id: "brand-detail",
    numeral: "IV",
    name: "Brand / Detail",
    short: "Detail",
    question: "How does identity become recognizable in lived experience?",
    role: "Make the idea recognizable in everyday encounters.",
  },
];

export const lensById: Record<LensId, Lens> = Object.fromEntries(lenses.map((l) => [l.id, l])) as Record<
  LensId,
  Lens
>;

export const lensHeading = "Four lenses. One connected practice.";

export const lensIntro =
  "Culture gives the work meaning. Place gives it context. Interiors shape behavior. Details make identity tangible. I move between these lenses throughout a project, using discoveries at one scale to sharpen decisions at another.";
