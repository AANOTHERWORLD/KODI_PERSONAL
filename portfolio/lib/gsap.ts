// GSAP is loaded client-side only, and ScrollTrigger is registered once here.
// Allowed uses: the landing scroll stage, the lens marquee, and the Work section.
import { gsap } from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";

let registered = false;

export function getGsap() {
  if (!registered && typeof window !== "undefined") {
    gsap.registerPlugin(ScrollTrigger);
    registered = true;
  }
  return { gsap, ScrollTrigger };
}
