import type { Asset, AssetType, LensId, ProjectBundle } from "../types";

// Projects restored from the Webflow portfolio. Each is a light case study: a proposition,
// a short narrative, and a gallery. Facts that have not been verified (years, locations,
// collaborators) are left empty and the page omits them rather than guessing.

type Img = { file: string; type: AssetType; caption: string; alt: string; lens: LensId; credit?: string };

interface Spec {
  id: string;
  title: string;
  kind: string;
  sequence: number;
  typeLabel: string;
  disciplines: string;
  tileSize: 1 | 2 | 3 | 4;
  lenses: LensId[];
  thesis: string;
  summary: string[];
  years: string;
  practice?: string;
  location: string;
  relatedProject: string;
  heroIndex: number;
  indexIndex: number;
  images: Img[];
}

const SENIOR_ROLE = "Senior Designer, Rapt Studio, working directly with the creative director and account lead";
const DIRECTOR_ROLE = "Design Director, Rapt Studio";
const DESIGNER_ROLE = "Designer, Collective Architecture";
const NEUTRAL_ROLE = "Rapt Studio, working directly with the creative director";
// Titles follow the project dates: Senior Designer before 2024, Design Director from 2024,
// with Lightspark, Club Gemini and A Place at the Table confirmed as Design Director,
// April Jean as Senior Designer, and Mama Rouge (2016) as Designer.
// Projects without a confirmed title carry none.
function roleFor(id: string) {
  if (id === "the-mark" || id === "april-jean") return SENIOR_ROLE;
  if (id === "mama-rouge") return DESIGNER_ROLE;
  if (["napa-retreat", "club-gemini", "place-at-table", "lightspark"].includes(id)) return DIRECTOR_ROLE;
  return NEUTRAL_ROLE;
}

function build(spec: Spec): ProjectBundle {
  const id = spec.id;
  const assets: Asset[] = spec.images.map((img, i) => ({
    id: `${id}-${String(i + 1).padStart(2, "0")}`,
    projectId: id,
    file: `${id}/${img.file}`,
    type: img.type,
    caption: img.caption,
    alt: img.alt,
    creator: img.credit ? img.credit.replace(/^Photography: /, "") : "",
    credit: img.credit ?? "",
    permission: "confirmed",
    lens: img.lens,
  }));
  return {
    project: {
      id,
      title: spec.title,
      slug: id,
      tier: "core",
      caseStudy: "light",
      inPdf: false,
      landingTile: true,
      thesis: spec.thesis,
      clientDisplayName: "",
      practice: spec.practice ?? "Rapt Studio",
      location: spec.location,
      years: spec.years,
      status: "completed",
      role: roleFor(id),
      scope: "",
      team: [],
      collaborators: [],
      lenses: spec.lenses,
      portfolioRole: spec.kind,
      typeLabel: spec.typeLabel,
      disciplines: spec.disciplines,
      sequence: spec.sequence,
      tileSize: spec.tileSize,
      relatedProject: spec.relatedProject,
      permission: "confirmed",
      heroAssetId: assets[spec.heroIndex - 1].id,
      indexAssetId: assets[spec.indexIndex - 1].id,
    },
    narrative: {
      projectId: id,
      summary: spec.summary,
      challenge: [],
      insight: [],
      vision: [],
      scaleTranslation: [],
      leadership: [],
      outcome: [],
      involvement: roleFor(id),
    },
    decisions: [],
    assets,
    claims: [],
  };
}

const specs: Spec[] = [
  {
    id: "lightspark",
    title: "Lightspark",
    kind: "Workplace",
    sequence: 9,
    typeLabel: "Workplace",
    disciplines: "Interiors, Brand",
    tileSize: 3,
    lenses: ["interiors-behavior", "brand-detail"],
    thesis: "A timber-and-steel workplace with room to focus, gather, and pause.",
    summary: [
      "Lightspark's workplace sits beneath exposed timber trusses, where a dark stair and black millwork volumes organize the floor into places to work, meet, and pause.",
      "Within that structure, a library alcove of collected objects, a lounge beneath the company mark, and a shared kitchen under a typographic light fixture give the brand a physical presence in everyday spaces.",
      "I led the design with the Rapt Studio team. The photographs show the completed interior.",
    ],
    years: "2025",
    location: "",
    relatedProject: "tinder-hq",
    heroIndex: 1,
    indexIndex: 6,
    images: [
      { file: "lightspark-01-open-floor.jpg", type: "photo", caption: "Open floor beneath timber trusses, with a long shared table in the foreground.", alt: "Open-plan workplace with exposed timber trusses, a large landscape artwork on the wall, and people at tables.", lens: "interiors-behavior" },
      { file: "lightspark-02-library-alcove.jpg", type: "photo", caption: "The library alcove, with collected objects on shelves and red seating below.", alt: "A lit timber alcove of shelves holding books, trophies, and objects above a counter with red banquette seats.", lens: "brand-detail" },
      { file: "lightspark-03-lounge-brand-mark.jpg", type: "photo", caption: "A lounge beneath the illuminated company mark.", alt: "A pale bench seat on a white wall with a backlit asterisk-shaped mark, beside a large plant and a person walking past.", lens: "brand-detail" },
      { file: "lightspark-04-entry-lounge.jpg", type: "photo", caption: "A lounge near the entry, in dark tones with a sofa on a low platform.", alt: "A dark room with track lighting, two people seated on a cream sofa on a low platform, and glazed doors beyond.", lens: "interiors-behavior" },
      { file: "lightspark-05-stair-table.jpg", type: "photo", caption: "A standing table beside the black stair and a shelving niche.", alt: "Two people talking at a tall black table beside a black stair and shelves, with a third person passing.", lens: "interiors-behavior" },
      { file: "lightspark-06-shared-kitchen.jpg", type: "photo", caption: "The shared kitchen and tables beneath a typographic light fixture.", alt: "A kitchen counter with two people and long timber tables below a white light panel printed with a grid of letters.", lens: "brand-detail" },
      { file: "lightspark-07-stair-overhead.jpg", type: "photo", caption: "The black stair seen from above, over the open floor.", alt: "View from above of a black stair, timber trusses, and desks on the floor below.", lens: "interiors-behavior" },
      { file: "lightspark-08-bookcase-doorway.jpg", type: "photo", caption: "A doorway framed by black bookcases with books and plants.", alt: "A black doorway flanked by shelves holding books, plants, and objects.", lens: "brand-detail" },
      { file: "lightspark-09-stair-descent.jpg", type: "photo", caption: "A person descending toward a lounge, seen from above.", alt: "Overhead view of a person carrying a coffee past a black table and a lounge chair.", lens: "interiors-behavior" },
    ],
  },
  {
    id: "mama-rouge",
    title: "Mama Rouge",
    kind: "Hospitality",
    sequence: 10,
    typeLabel: "Restaurant",
    disciplines: "Interiors, Hospitality",
    tileSize: 3,
    lenses: ["interiors-behavior", "brand-detail"],
    thesis: "A restaurant interior built from red lacquer, pattern, and light.",
    summary: [
      "Mama Rouge is a restaurant interior in which saturated red lacquer, patterned banquettes, and warm timber tables meet a tin ceiling and an oval soffit holding a golden fiber chandelier.",
      "Cast ornamental screens, a mirrored back bar, and a corridor of streaking yellow and red light lead guests between rooms, so detail and atmosphere carry the identity as much as the plan does.",
      "I worked on this project as a designer at Collective Architecture. The photographs show the completed restaurant.",
    ],
    years: "2016",
    practice: "Collective Architecture",
    location: "",
    relatedProject: "kilroy-oyster-point",
    heroIndex: 1,
    indexIndex: 4,
    images: [
      { file: "mama-rouge-01-dining-room.jpg", type: "photo", caption: "The dining room beneath an oval ceiling with a golden fiber chandelier.", alt: "Restaurant dining room with timber tables, patterned banquettes, a red bar at the back, and a glowing oval ceiling with a chandelier.", lens: "interiors-behavior" },
      { file: "mama-rouge-02-timber-tile-wall.jpg", type: "photo", caption: "A banquette and a wall of timber tiles beside red lacquer panelling.", alt: "Table beside a patterned banquette, with a tall wall of timber tiles and red panelling.", lens: "brand-detail" },
      { file: "mama-rouge-03-timber-tile-wall-tall.jpg", type: "photo", caption: "The timber-tile wall rising above a patterned banquette.", alt: "Tall view of a wall of timber tiles above a long banquette and a row of set tables.", lens: "brand-detail" },
      { file: "mama-rouge-04-dining-room-wide.jpg", type: "photo", caption: "A wide view of the dining room and bar.", alt: "Wide view of a restaurant with a chandelier in an oval ceiling, red bar, and many set tables.", lens: "interiors-behavior" },
      { file: "mama-rouge-05-bar.jpg", type: "photo", caption: "The bar, with red stools, a patterned banquette, and a mirrored back wall.", alt: "A bar with red stools below shelves of bottles, in front of a patterned banquette.", lens: "interiors-behavior" },
      { file: "mama-rouge-06-ornamental-screen.jpg", type: "photo", caption: "A cast ornamental screen with red bar stools beyond.", alt: "Close view of a black cast screen pattern with red bar stools blurred behind it.", lens: "brand-detail" },
      { file: "mama-rouge-07-dining-room-length.jpg", type: "photo", caption: "The dining room seen down its length, with the chandelier ceiling above.", alt: "Dining room seen from the end of a table, with a glowing oval ceiling and red bar at the far end.", lens: "interiors-behavior" },
      { file: "mama-rouge-08-light-corridor.jpg", type: "photo", caption: "A corridor of streaking yellow and red light leading to a painted figure.", alt: "Narrow corridor with patterned tile floor, bands of yellow and red light on one wall, and a painted figure at the end.", lens: "brand-detail" },
      { file: "mama-rouge-09-restroom.jpg", type: "photo", caption: "A red restroom with a mirror reflecting the corridor light.", alt: "Restroom with red walls, a white basin, and a mirror showing bands of yellow and red light.", lens: "brand-detail" },
      { file: "mama-rouge-10-red-side-table.jpg", type: "photo", caption: "A red side table among banquettes and dining tables.", alt: "A red table with curved legs beside a patterned banquette, timber tables, and a patterned floor.", lens: "interiors-behavior" },
      { file: "mama-rouge-11-banquette-corridor.jpg", type: "photo", caption: "A banquette with the painted corridor beyond.", alt: "A banquette and table in warm tones with a wall lamp, and a corridor with a painted figure in the distance.", lens: "brand-detail" },
    ],
  },
  {
    id: "april-jean",
    title: "Bar April Jean",
    kind: "Hospitality brand",
    sequence: 11,
    typeLabel: "Bar and identity",
    disciplines: "Brand identity, Signage, Hospitality",
    tileSize: 2,
    lenses: ["brand-detail", "interiors-behavior"],
    thesis: "A bar identity carried from wordmark to sign to the glass.",
    summary: [
      "Bar April Jean pairs a flowing script wordmark with a palette of rust red and deep green, and carries it through a collage illustration style, menus, social posts, and a projecting sign on a green corner building.",
      "At the bar itself, the identity meets the everyday: hands, glasses, and printed menus on stands, with warm timber and a full back bar.",
      "As senior designer, I worked directly with the creative director and account lead to develop concepts and design strategy, from early development through delivery and execution. The images combine photographs of the bar with identity and signage design.",
    ],
    years: "2024",
    location: "",
    relatedProject: "mama-rouge",
    heroIndex: 4,
    indexIndex: 1,
    images: [
      { file: "april-jean-01-brand-illustration.png", type: "graphic", caption: "Brand illustration: a hand holding a mint cocktail, with the wordmark.", alt: "Collage illustration of a hand holding a tall mint cocktail on a dark green ground, with the April Jean wordmark.", lens: "brand-detail" },
      { file: "april-jean-02-wordmark.jpg", type: "graphic", caption: "The April Jean wordmark in cream script on rust red.", alt: "The words Bar April Jean in cream script on a rust-red field.", lens: "brand-detail" },
      { file: "april-jean-03-social-posts.jpg", type: "graphic", caption: "Social posts of cocktails in hand.", alt: "Three phone screens showing hands holding cocktails in red, orange, and amber on a pink patterned ground.", lens: "brand-detail" },
      { file: "april-jean-04-corner-exterior.jpg", type: "photo", caption: "The bar on a street corner, with its green facade.", alt: "A green two-storey corner building with a small projecting sign, on a street with a parked white van.", lens: "interiors-behavior" },
      { file: "april-jean-05-projecting-sign.jpg", type: "photo", caption: "The projecting BAR sign on the green facade.", alt: "A rounded blade sign reading BAR mounted on a sage-green facade.", lens: "brand-detail" },
      { file: "april-jean-06-bar-service.jpg", type: "photo", caption: "A bartender at work behind the bar.", alt: "A tattooed bartender pouring at a bar with juices, fruit, and glasses.", lens: "interiors-behavior" },
      { file: "april-jean-07-bar-menus.jpg", type: "photo", caption: "Bartenders at the bar with printed menus on stands.", alt: "Two bartenders in caps at a bar with printed menus on small stands and a full back bar behind.", lens: "interiors-behavior" },
      { file: "april-jean-08-illuminated-sign.jpg", type: "graphic", caption: "Signage design: April Jean, open daily 'til late, drinks and jams.", alt: "Illuminated sign reading April Jean, Open daily 'til late, Drinks and Jams, with a small flower mark.", lens: "brand-detail" },
      { file: "april-jean-09-print-collateral.jpg", type: "graphic", caption: "Printed collateral: a menu and a poster collage.", alt: "A printed menu and a collage poster with cocktail imagery and the April Jean wordmark.", lens: "brand-detail" },
    ],
  },
  {
    id: "the-mark",
    title: "The Mark",
    kind: "Lobby and amenity",
    sequence: 12,
    typeLabel: "Lobby and terrace",
    disciplines: "Interiors, Architecture",
    tileSize: 3,
    lenses: ["architecture-place", "brand-detail"],
    thesis: "A lobby drawn with a single line of light.",
    summary: [
      "At The Mark, a continuous line of white light loops across a lobby of black stone, vertical timber, and pale terrazzo, drawing the eye from the entry through to the reception desk.",
      "Outside, a terrace of small black tables, pale paving, and planting continues the quiet palette.",
      "As senior designer, I worked directly with the creative director and account lead to develop concepts and design strategy, from early development through delivery and execution. The photographs show the completed lobby and terrace; two further images are reference studies.",
    ],
    years: "2021",
    location: "Los Angeles",
    relatedProject: "kilroy-oyster-point",
    heroIndex: 6,
    indexIndex: 2,
    images: [
      { file: "the-mark-01-light-line-install.png", type: "photo", caption: "A continuous line of light mounted over dark stone panels during installation.", alt: "A white line of light curving across dark veined stone panels, with an orange ladder at the right.", lens: "brand-detail" },
      { file: "the-mark-02-reception.jpg", type: "photo", caption: "The reception desk in black stone against vertical timber, under looping lines of light.", alt: "A reception desk of black stone with a person behind it, against vertical timber slats and looping white light lines overhead.", lens: "interiors-behavior" },
      { file: "the-mark-03-terrace.jpg", type: "photo", caption: "The terrace: small black tables on pale paving beside planting, seen from above.", alt: "View from above of round black tables and chairs on pale paving beside a planted bed.", lens: "architecture-place" },
      { file: "the-mark-04-light-study.jpg", type: "concept", caption: "Reference: the lobby light line beside a black-and-white study of a light drawing.", alt: "Two images: a lobby with a white light line over dark panelling, and a black-and-white room with a looping light drawing.", lens: "brand-detail" },
      { file: "the-mark-05-material-reference.jpg", type: "concept", caption: "Reference: a warm timber panel and a classical building.", alt: "A hand resting on a warm timber panel, beside a photograph of a building crowned with a large classical capital.", lens: "brand-detail" },
      { file: "the-mark-06-lobby.jpg", type: "photo", caption: "The lobby, with looping lines of light above low black seating.", alt: "Wide lobby with dark panelled walls, looping white light lines on the ceiling, and low black seating with two people.", lens: "architecture-place" },
    ],
  },
  {
    id: "club-gemini",
    title: "Club Gemini",
    kind: "Experiential",
    sequence: 13,
    typeLabel: "Event lounge",
    disciplines: "Experience design, Environments",
    tileSize: 2,
    lenses: ["brand-detail", "interiors-behavior"],
    thesis: "A violet-lit lounge made for an evening gathering.",
    summary: [
      "Club Gemini turns a room into an evening lounge: deep violet velvet curtains, low blue sofas, candlelight, and dark florals, all under saturated purple and magenta light.",
      "The details, a hand-held glass, a menu card beside a candle, a coffee table of flowers, keep the atmosphere intimate and specific.",
      "I led the design with the Rapt Studio team. The images are event documentation.",
    ],
    years: "2024",
    location: "",
    relatedProject: "napa-retreat",
    heroIndex: 1,
    indexIndex: 2,
    images: [
      { file: "club-gemini-01-velvet-curtains.jpg", type: "photo", caption: "A hand holding a glass against violet velvet curtains.", alt: "A hand in magenta light holding a glass in front of dark purple velvet curtains.", lens: "brand-detail" },
      { file: "club-gemini-02-lounge.jpg", type: "photo", caption: "The lounge, with velvet curtains, deep blue sofas, and candlelit flowers.", alt: "Lounge with floor-length purple curtains, a dark blue sofa and armchair, a low table with flowers, and a lit candle.", lens: "interiors-behavior" },
      { file: "club-gemini-03-florals-menu.jpg", type: "photo", caption: "A floral arrangement and a menu card by candlelight.", alt: "Large dark floral arrangement with a lit pillar candle and a small pink menu card against blue curtains.", lens: "brand-detail" },
    ],
  },
  {
    id: "napa-retreat",
    title: "Napa Leadership Retreat",
    kind: "Experiential event",
    sequence: 14,
    typeLabel: "Leadership retreat",
    disciplines: "Experience design, Environments, Print",
    tileSize: 2,
    lenses: ["culture-strategy", "brand-detail"],
    thesis: "A leadership retreat shaped by textile, table, and harvest.",
    summary: [
      "The Napa Leadership Retreat gathered leaders for a multi-day program, with the setting drawn from textile, table, and harvest: draped cream fabric, warm pools of light, plants on plinths, and seasonal centerpieces.",
      "Printed materials, a green menu card, and arrangements of anthurium, citron, and cabbage made the details of the table part of the program.",
      "I led the design with the Rapt Studio team. The images are event documentation.",
    ],
    years: "2024",
    location: "Napa Valley, California",
    relatedProject: "club-gemini",
    heroIndex: 1,
    indexIndex: 5,
    images: [
      { file: "napa-retreat-01-draped-backdrop.jpg", type: "photo", caption: "Draped cream fabric as a backdrop.", alt: "Folds of cream fabric draped over a wall in warm light.", lens: "brand-detail" },
      { file: "napa-retreat-02-draped-screen.jpg", type: "photo", caption: "A draped fabric screen above a long table with greenery.", alt: "A tall screen of draped cream fabric above a long table, with greenery in warm light.", lens: "interiors-behavior" },
      { file: "napa-retreat-03-printed-materials.jpg", type: "photo", caption: "Printed materials and plants on a plinth.", alt: "A stack of printed booklets on a pale plinth beside a leafy plant, lit in warm tones.", lens: "brand-detail" },
      { file: "napa-retreat-04-plinths.jpg", type: "photo", caption: "Plinths with plants and printed materials in warm light.", alt: "Pale plinths holding plants and printed materials against a warm wall.", lens: "brand-detail" },
      { file: "napa-retreat-05-seasonal-centerpiece.jpg", type: "photo", caption: "A seasonal centerpiece of anthurium, citron, and cabbage.", alt: "A centerpiece of anthurium, ferns, a pale cabbage, a citron, and moss on a table.", lens: "brand-detail", credit: "Photography: Sabine Scherer" },
      { file: "napa-retreat-06-place-setting.jpg", type: "photo", caption: "A place setting with a green printed menu.", alt: "A plate with a green printed menu and cutlery, among greens, citrus, and flowers.", lens: "brand-detail" },
    ],
  },
  {
    id: "place-at-table",
    title: "A Place at the Table",
    kind: "Experience and concept",
    sequence: 15,
    typeLabel: "Dinner experience",
    disciplines: "Experience design, Concept",
    tileSize: 2,
    lenses: ["culture-strategy", "brand-detail"],
    thesis: "A dinner designed around the shared table.",
    summary: [
      "A Place at the Table is a dinner built around one long shared table: candles, green stemware, blue-patterned plates, folded napkins, and small arrangements of flowers.",
      "Guests carry their own chairs to the table, share dishes, and gather at the end around a cake, so the evening is made by the people at it as much as by the setting.",
      "I led the design with the Rapt Studio team. The images are event documentation.",
    ],
    years: "2024",
    location: "",
    relatedProject: "napa-retreat",
    heroIndex: 3,
    indexIndex: 1,
    images: [
      { file: "place-at-table-01-celebration-cake.jpg", type: "photo", caption: "A celebration cake at the table, with hands reaching in.", alt: "A white cake decorated with orange flowers on a table, with several hands around it.", lens: "culture-strategy" },
      { file: "place-at-table-02-cake-candle.jpg", type: "photo", caption: "The cake, with a candle and a knife.", alt: "A white cake with strawberries and a candle, a knife held above it, among glasses and bottles.", lens: "culture-strategy" },
      { file: "place-at-table-03-place-settings.jpg", type: "photo", caption: "Place settings with candles and green stemware, seen from above.", alt: "Overhead view of place settings with blue-patterned plates, olive napkins, candles, and green stemware.", lens: "brand-detail" },
      { file: "place-at-table-04-candles-glassware.jpg", type: "photo", caption: "Candles, green glassware, and a bottle on the table.", alt: "Close view of candles in glass holders, green stemware, a clear bottle, and a folded place card.", lens: "brand-detail" },
      { file: "place-at-table-05-candlelit-setting.jpg", type: "photo", caption: "A candlelit place setting with a tall candle and wine.", alt: "A table with a tall candle, a green wine bottle, a small flower vase, and a blue-patterned plate.", lens: "brand-detail" },
      { file: "place-at-table-06-shared-dish.jpg", type: "photo", caption: "Guests at the table sharing a dish.", alt: "Guests seated close at a table, one person turned toward a shared dish of flatbread.", lens: "culture-strategy" },
      { file: "place-at-table-07-carrying-chairs.jpg", type: "photo", caption: "A guest carrying a chair to the table.", alt: "Two people crossing a bright room, one carrying a pale wooden chair.", lens: "culture-strategy" },
      { file: "place-at-table-08-long-table.jpg", type: "photo", caption: "The long table lined with guests.", alt: "A very long table in a bright room with guests seated on both sides and candles along its length.", lens: "culture-strategy" },
      { file: "place-at-table-09-after-the-meal.jpg", type: "photo", caption: "Plates after the meal, with candles and flowers.", alt: "Used plates with greens, candles, and white carnations on a table, and guests laughing in the background.", lens: "brand-detail" },
      { file: "place-at-table-10-table-at-night.jpg", type: "photo", caption: "The long table at night.", alt: "A long table lit by candles in a dim room with a large window at the far end.", lens: "culture-strategy" },
    ],
  },
];

export const moreWork: ProjectBundle[] = specs.map(build);
