# LSD Running: media prep for the portfolio (Claude Cowork)

Goal: turn the LSD review package and promo film into individual, web-ready files in the project hub, so the website team can import them. Do not edit, crop or retouch any original. Work from copies.

## Where things are (Google Drive, Rapt account)
- LSD hub folder: https://drive.google.com/drive/folders/1UAwhenurtPph5CdIpv0Cn32WBLz9faT2
  - `LSD Running - Narrative and Website Resources - 2026-10-14.zip` (38 MB, file id 1KoLNQWg2U5hCy8rumMvb8KR-LmtRSXMG)
  - `LSD Running - Promo Video.mp4` (19 MB, file id 1lzWtOOPIMYGGRjp6i9tZV8_ky3eyLHNf)
  - Subfolders to upload into:
    - Photography: 1WWXbCTWeJqDOutcTWxfFmtGKVwaPUvNX
    - Webflow Source Images: 15Zzmv59EPNSfKoAUICnhe06h4db44XHG
    - Renderings & Process: 1-dy4Ufz69O9r2Nt8Gg9o8F4bdDpBlc_q

## Why this is needed
The connector the website team uses cannot download files over 10 MB, so the ZIP and the film are unreachable. Every deliverable below must be an individual file under 10 MB.

## Steps
1. Download the ZIP and the film. Extract the ZIP into a new empty folder. Open `gallery.html` to see how the package is organised.
2. **Photography.** Upload each file in the package's `Photography/` folder as an individual file to the hub `Photography` subfolder, keeping its original filename (IMG_0157.jpg, IMG_0173.jpg, IMG_0386.jpg, IMG_0400.jpg, IMG_0407.jpg, IMG_0419.jpg, IMG_0429.jpg and the rest). Skip any file already in that folder with the same name and size. If a file is over 9 MB, also upload a copy resized to 4000 px on the long edge, JPEG quality 90, named `<original name>-web.jpg`.
3. **Web derivatives.** The package contains 19 web-ready JPG derivatives. Upload each individually to `Webflow Source Images`, original filenames.
4. **Film stills.** Capture full-resolution stills from the promo film and save as JPG (quality 92, no scaling):
   - `video-06s-interior.jpg` (at 6 seconds)
   - `video-15s-bench-and-space.jpg` (at 15 seconds)
   - `video-30s-wordmark.jpg` (at 30 seconds)
   - Also capture one still at each clear change of scene or camera position, named `video-<seconds>s-<short-description>.jpg` (for example `video-22s-boulder-display.jpg`). Choose frames that are sharp and well exposed, not mid-transition or motion-blurred. Aim for 8 to 12 stills in total.
   - Upload all stills to `Renderings & Process`. These are film stills, not original photographs. Say so in the manifest.
5. **Web film.** Encode the promo film as H.264 MP4, no audio track unless the original has one worth keeping, 1280 px wide, 24 or 25 fps, 2-pass or CRF 23, under 9 MB. Name it `LSD Running - Promo Video (web).mp4`. Also export a poster frame from 1 second in as `LSD Running - Promo Video (poster).jpg`. Upload both to the hub root folder. Keep the original film untouched.
6. **Manifest.** Create `LSD upload manifest.md` in the hub root listing every uploaded file: filename, folder, pixel dimensions, size in KB, Drive file id, and whether it is an original photograph, a web derivative or a film still.

## Checks before finishing
- Every uploaded file is under 10 MB and opens in Drive.
- No original was modified or overwritten.
- Stills are sharp and match the filenames you gave them.
- The manifest lists every file.

## Do not
- Do not describe film stills as photographs.
- Do not upload the ZIP's PDFs or notes as images.
- Do not guess a photographer. The credit is "supplied by Rapt Studio" until Jamel confirms a name.

When finished, tell Jamel the manifest file name so the website team can import the images.
