import type { ProjectBundle } from "../types";
import { intuitTurbotaxRetail } from "./intuit-turbotax-retail";
import { googleGso } from "./google-gso";
import { tinderHq } from "./tinder-hq";
import { lsdRunning } from "./lsd-running";
import { kilroyOysterPoint } from "./kilroy-oyster-point";
import { openaiTokyo } from "./openai-tokyo";
import { wattPlaza } from "./watt-plaza";
import { googleTokyoPartnerPlex } from "./google-tokyo-partner-plex";

// To add a project: create a file in this folder that exports a ProjectBundle, add the
// source images to public/projects/<slug>/, and append the bundle here. Layout code never
// changes. The work index orders entries by project.sequence.
export const projectBundles: ProjectBundle[] = [
  intuitTurbotaxRetail,
  googleGso,
  tinderHq,
  lsdRunning,
  kilroyOysterPoint,
  openaiTokyo,
  wattPlaza,
  googleTokyoPartnerPlex,
];
