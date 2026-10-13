# One Vision. Multiple Scales.

Portfolio site for Jamel Williams, Design Director. A fully static Next.js (App Router) build with a typed content layer, verification and permission gates, a build-time image pipeline, and a custom cursor and canvas trail.

Everything under this `portfolio/` folder is self-contained. Nothing in the rest of the repository is required to build or deploy it.

## Contents

1. [Local setup](#local-setup)
2. [How the site is organized](#how-the-site-is-organized)
3. [Content: adding or editing a project](#content-adding-or-editing-a-project)
4. [Draft mode and the content gates](#draft-mode-and-the-content-gates)
5. [Images](#images)
6. [Portfolio PDF and CV](#portfolio-pdf-and-cv)
7. [Debugging](#debugging)
8. [Deploying to free static hosting](#deploying-to-free-static-hosting)
9. [Custom domain](#custom-domain)
10. [Quality checks](#quality-checks)

## Local setup

Requirements: Node 20 or newer (built and tested on Node 22) and npm.

```bash
cd portfolio
npm install
npm run dev
```

Open http://localhost:3000. The first `npm run dev` serves source images directly; run `npm run images` once to generate the responsive WebP renditions and the image manifest (this also happens automatically before every `npm run build`).

To preview the drafts (projects and claims that are still awaiting permission or verification), copy `.env.example` to `.env.local` and set:

```
NEXT_PUBLIC_SHOW_DRAFTS=true
```

Production build:

```bash
npm run build
```

`npm run build` runs the `prebuild` image pipeline, then `next build`, which writes a self-contained static site to `out/`. There is no server. Serve `out/` with any static file host, or locally with `npx serve out`.

## How the site is organized

```
portfolio/
  app/                 Routes (App Router). Layout, Home, Work index, project pages, Approach, About, Contact.
  components/          Shared UI. Picture (responsive img), cursor and trail, lens key, work entry, header, footer.
  content/             The content layer. Typed records: projects, profile, portfolio, lenses, approach.
    projects/          One file per project, plus index.ts which lists them.
    generated/         Image manifest written by the pipeline (gitignored).
  lib/                 Content loader and gates, image resolver, debug logger, file checks, base path.
  public/
    projects/<slug>/   Source images, untouched. Add files here.
    generated/         WebP renditions written by the pipeline (gitignored).
    fonts/             Self-hosted Fraunces and Inter.
  scripts/
    optimize-images.mjs  Build-time image pipeline (sharp).
    check-copy.mjs       Fails if an em dash appears anywhere in code, content, or docs.
  firebase.json        Ready config for Firebase Hosting.
  next.config.ts       Static export, trailing slashes, optional base path, unoptimized images.
```

Pages: Home (six sections), `/work/` (editorial sequence), `/work/<slug>/` (shared project template), `/approach/`, `/about/`, `/contact/`. Navigation: Work, Approach, About, Contact. The name returns to Home.

The content layer is deliberately plain TypeScript. To move it to a headless CMS later (for example Sanity), replace the imports at the top of `lib/content.ts` with a fetch from the CMS that returns the same `ProjectBundle` shapes defined in `content/types.ts`. Components never read content files directly.

## Content: adding or editing a project

1. Create `content/projects/<slug>.ts` exporting a `ProjectBundle` (copy an existing file as a template). The bundle holds five records:
   - `project`: title, slug, thesis, client display name, location, years, status, role, scope, team, collaborators, lenses, `sequence`, `tileSize`, `homeFeature`, `relatedProject`, `permission`, and the hero asset id.
   - `narrative`: challenge, insight, vision, `scaleTranslation` (an ordered image sequence with lens tags and captions), leadership, outcome, reflection, and the precise personal involvement.
   - `decisions`: two or three decisive choices, each with question, choice, rationale, tradeoff, and supporting asset ids.
   - `assets`: every image with a stable id, file path (relative to `public/projects/`), type (`photo`, `render`, `concept`, `plan`, `diagram`, `process`), caption, alt text, creator, credit, and permission.
   - `claims`: statements that need verification before they can appear in production (see gates below).
2. Put the source images in `public/projects/<slug>/`. JPG, PNG, WebP, TIFF, and SVG are supported. SVG diagrams are served as they are.
3. Add the bundle to the list in `content/projects/index.ts`.
4. Set `sequence` to place it in the Work index. The index is an editorial order and is never rearranged by the layout. `tileSize` (1 to 4) sets the image scale in the index, mapped between `MIN_TILE_PX = 220` and `MAX_TILE_PX = 620`.
5. Run `npm run build`. The image pipeline picks up the new folder automatically.

Nothing in `app/` or `components/` needs to change.

Project slots:
- `slot: "core"` and `"optional"` render whenever their permission is confirmed.
- `slot: "candidate"` renders only in draft mode. Use it to keep a researched project ready without publishing it.

Profile and contact copy live in `content/profile.ts` and `content/portfolio.ts`. Items marked `PLACEHOLDER` are stand-ins and should be replaced before launch.

## Draft mode and the content gates

Three gates are enforced during the build by `lib/content.ts`:

- **Permission gate.** A project or asset with `permission: "pending"` is excluded from production builds. In draft mode it renders with a visible "Draft: permission pending" marker.
- **Verification gate.** A claim with `status: "verified"` renders everywhere. `awaiting` renders only in draft mode, highlighted with an "Awaiting verification" marker. `omit` never renders.
- **Candidate slot.** Candidate projects render only in draft mode.

Draft mode is enabled with `NEXT_PUBLIC_SHOW_DRAFTS=true` at build time. Production builds default to off. Every excluded project, asset, and claim is printed to the build log, prefixed `[portfolio:content]`, so nothing disappears silently.

As delivered, every project is `permission: "pending"` because client and studio sign-off has not been confirmed. A production build therefore ships the full site structure with empty Work and feature sections. To publish a project, change its `permission` to `"confirmed"` in its content file. To publish a claim, change its `status` to `"verified"`.

Keep intent separate from observation and measured result in all copy. "Designed to encourage interaction" never becomes "increased interaction".

## Images

Static export turns off Next.js runtime image optimization (`images.unoptimized: true`), so optimization happens at build time instead.

- `scripts/optimize-images.mjs` runs as the npm `prebuild` step. It reads every image in `public/projects/<slug>/`, writes WebP renditions at 480, 960, 1440, and 2000 pixels wide (never upscaling) to `public/generated/<slug>/`, and records intrinsic dimensions in `content/generated/image-manifest.json`.
- `components/Picture.tsx` reads the manifest and outputs `srcset`, `sizes`, explicit `width` and `height`, `loading="lazy"` below the fold, and a caption with the asset type, credit, and any draft marker.
- Source images are never modified. Generated folders are gitignored. Re-running the script only rebuilds renditions whose source changed.
- Run it on its own with `npm run images`, or with `--verbose` for a per-file log.

Large originals (for example 80 MB photography JPGs) can go straight into `public/projects/<slug>/`; only the generated renditions are served.

## Portfolio PDF and CV

Drop `portfolio.pdf` and `cv.pdf` into `public/`. At build time `lib/files.ts` checks whether each file exists and renders its links (footer, About, Contact, Home invitation) only when it does. Rebuild after adding or removing either file.

## Debugging

A guarded logger in `lib/debug.ts` is off by default. Enable it with `NEXT_PUBLIC_DEBUG=true` (build and browser) or by opening any page with `?debug=1` (the flag persists for the browser session). The cursor, trail, lens key, parallax, and image pipeline log through it with the prefix `[portfolio:...]`.

Z-index values are documented at the top of `app/globals.css` and in `components/CursorTrail.tsx`.

## Deploying to free static hosting

The build output is a plain folder of HTML, CSS, JS, and assets. It runs unchanged on every host below. Build settings that are the same everywhere:

- Root directory: `portfolio`
- Install command: `npm install`
- Build command: `npm run build`
- Output directory: `out`
- Node version: 20 or newer

Set `NEXT_PUBLIC_SHOW_DRAFTS=true` as a build environment variable on a host if you want a private draft preview deployment. Leave it unset for production.

### Vercel (Hobby plan, primary)

1. Push this repository to GitHub.
2. In Vercel, choose Add New, Project, and import the repository.
3. Set Root Directory to `portfolio`. Framework preset: Next.js. Vercel reads `output: 'export'` and serves `out/` as static files.
4. Deploy. Every push to the connected branch redeploys automatically; pull requests get preview URLs.
5. Environment variables (optional): `NEXT_PUBLIC_SHOW_DRAFTS` for a draft preview, `NEXT_PUBLIC_DEBUG` for logging.

### Cloudflare Pages

1. In the Cloudflare dashboard, open Workers and Pages, Create, Pages, Connect to Git.
2. Select the repository. Build settings: framework preset None, build command `npm run build`, build output directory `out`, root directory `portfolio`.
3. Add environment variable `NODE_VERSION` = `20`.
4. Save and deploy. Pushes redeploy automatically.

### Netlify

1. Add new site, Import an existing project, pick the repository.
2. Base directory `portfolio`, build command `npm run build`, publish directory `portfolio/out`.
3. Deploy. Netlify serves the folder-style routes directly because `trailingSlash: true` writes `index.html` into each route folder.

### GitHub Pages

GitHub Pages serves from a subpath (`https://<user>.github.io/<repo>/`) unless you attach a custom domain. The site supports this through `NEXT_PUBLIC_BASE_PATH`.

1. In the repository settings, Pages, set Source to GitHub Actions.
2. Add `.github/workflows/portfolio-pages.yml`:

```yaml
name: Deploy portfolio to GitHub Pages
on:
  push:
    branches: [main]
  workflow_dispatch:
permissions:
  contents: read
  pages: write
  id-token: write
jobs:
  build:
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: portfolio
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: npm
          cache-dependency-path: portfolio/package-lock.json
      - run: npm ci
      - run: npm run build
        env:
          NEXT_PUBLIC_BASE_PATH: /${{ github.event.repository.name }}
      - uses: actions/upload-pages-artifact@v3
        with:
          path: portfolio/out
  deploy:
    needs: build
    runs-on: ubuntu-latest
    environment:
      name: github-pages
    steps:
      - id: deployment
        uses: actions/deploy-pages@v4
```

3. Push to `main`. The site appears at `https://<user>.github.io/<repo>/`.
4. With a custom domain attached to GitHub Pages, remove the `NEXT_PUBLIC_BASE_PATH` line so the site builds for the root.

Note for this repository: the root of `aanotherworld.github.io/KODI_PERSONAL/` already serves the Kodi add-on repository. Deploy the portfolio to its own repository or host, or to a subpath that does not collide with `repo.zip` and `zips/`.

### Firebase Hosting

`firebase.json` is included and serves `out/` with clean URLs and long cache headers for images and static assets.

```bash
npm install -g firebase-tools
firebase login
firebase init hosting   # choose an existing project, keep firebase.json as is, answer No to overwriting
npm run build
firebase deploy --only hosting
```

## Custom domain

1. Buy the domain anywhere (Cloudflare Registrar, Namecheap, Google Domains successor, etc.).
2. In the host's dashboard, add the domain:
   - Vercel: Project, Settings, Domains, Add. Vercel shows the records to create.
   - Cloudflare Pages: Custom domains, Set up a custom domain.
   - Netlify: Domain management, Add a domain.
   - GitHub Pages: Settings, Pages, Custom domain. Also commit a `public/CNAME` file containing the domain so it survives rebuilds.
   - Firebase: Hosting, Add custom domain.
3. At the DNS provider, create the records the host shows: usually an `A` record on the apex pointing at the host's IP, and a `CNAME` on `www` pointing at the host. Vercel and Cloudflare offer `ALIAS`-style apex records.
4. Wait for the certificate to issue (minutes to an hour). All hosts above provide HTTPS automatically.
5. Update `NEXT_PUBLIC_BASE_PATH` to empty if the site previously built for a subpath, and redeploy.

## Quality checks

```bash
npm run typecheck     # TypeScript
npm run check:copy    # fails on any em dash in code, content, or docs
npm run build         # image pipeline + static export, prints every gated exclusion
```

Accessibility notes: all interactive elements are keyboard reachable with visible focus; the custom cursor never replaces focus styling; the lens key uses `aria-pressed` and a live region; the cursor and trail are disabled on coarse pointers and under `prefers-reduced-motion`, where the native cursor is restored; every image carries alt text, a caption, and a credit from its asset record; important information never depends on hover.
