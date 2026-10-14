import type { ProjectBundle } from "../types";
import { intuitTurbotaxRetail } from "./intuit-turbotax-retail";
import { googleGso } from "./google-gso";
import { tinderHq } from "./tinder-hq";
import { lsdRunning } from "./lsd-running";
import { googleRoom98 } from "./google-room-98";
import { openai } from "./openai";
import { kilroyOysterPoint } from "./kilroy-oyster-point";
import { wattPlaza } from "./watt-plaza";
import { googleTokyoPartnerPlex } from "./google-tokyo-partner-plex";
import { moreWork } from "./more-work";

// To add a project: create a file in this folder that exports a ProjectBundle, add the source
// images to public/projects/<slug>/, and append the bundle here. Layout code never changes.
// Core projects (tier: core) lead the Work index in sequence order and appear in the PDF.
// Extended projects (tier: extended) follow under "More work" with lighter pages.
export const projectBundles: ProjectBundle[] = [
  intuitTurbotaxRetail,
  googleGso,
  tinderHq,
  lsdRunning,
  googleRoom98,
  openai,
  kilroyOysterPoint,
  wattPlaza,
  googleTokyoPartnerPlex,
  ...moreWork,
];
