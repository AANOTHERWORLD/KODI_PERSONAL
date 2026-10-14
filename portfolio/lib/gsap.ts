// GSAP is loaded client-side only, and ScrollTrigger is registered once here.
// Uses: the lens marquee, the portrait parallax, and the footer curtain (all scroll scrubs).
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
