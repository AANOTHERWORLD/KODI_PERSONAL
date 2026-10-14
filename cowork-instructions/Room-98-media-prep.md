# Google Room 98: media prep for the portfolio (Claude Cowork)

Goal: unpack the Room 98 package into individual files, make web-ready copies, and turn the three animated GIFs into lightweight looping video with still fallbacks. Do not edit or retouch any original. Work from copies.

## Where things are (Google Drive, Rapt account)
- Room 98 hub folder: https://drive.google.com/drive/folders/13LSZETiNXmf8-SlJY3KjU66p0SjAxwbB
  - Four ZIPs, `Room 98 - Website imagery and sources - part 1` to `part 4` (file ids 1PO1LMGyuCj_q2lCwKn7pudCoqlyqZkgs, 1fhh1iqJqSKylhFjq29kVHq1uulcuOWMD, 11_RK8_vROMvP0T7E6vYYX3RTP2OaFY-i, 14Z2A42fbFosyPt87GSMCrX-8IXOj3Y84). They are ordinary ZIPs with different contents. Extract all four into one new empty folder and merge the folders.
  - Subfolders to upload into:
    - Photography: 1VM1AjyNLJg-j0EW8sppjwGWdRqy6uIS5
    - Renderings & Process: 1ZD56RlsjwhQIKOl1tsISPTqHi_p3bcU0
    - Drawings & Diagrams: 1CWlzqTXt183hk-OYOJTK1lv_8zDVYAsv
    - Project Information: 1uhLEGTeL4lFo-L6-kTFBxS8u58cjfTHV

## Why this is needed
The connector the website team uses cannot download files over 10 MB. The photographs are up to 8256 px wide and the GIFs are 5 to 8 MB each. Every deliverable must be an individual file under 10 MB.

## Steps
1. Extract the four ZIPs into one folder. Open `gallery.html` and `selected-sequence.jpg` to see the recommended sequence.
2. **Photography (30 files, credit MO Studio).** For each file in `Photography/`:
   - Keep the original filename.
   - If it is under 9 MB, upload it as is to the hub `Photography` subfolder.
   - If it is over 9 MB, upload a web copy instead: 4000 px on the long edge, JPEG quality 90, named `<original name>-web.jpg`. Never upscale a file that is already smaller than 4000 px.
   - Do not rename or reorder files. The filenames carry the room and shot number.
3. **Renderings.** Upload each file in `Renderings/` individually to `Renderings & Process`. Resize to 3000 px on the long edge, quality 88, if over 9 MB, and keep the name with `-web` added. These are design renderings, not photographs.
4. **Plans and diagrams.** Upload `Plans/LA CEC Floor Plan.jpg` and each file in `Diagrams/` to `Drawings & Diagrams`. Resize only if over 9 MB.
5. **Motion (three GIFs).** For each of `GIF_Presentation.gif`, `GIF_Collaboration.gif` and `GIF_Deliberation.gif`:
   - Export a looping H.264 MP4, no audio, 1600 px wide, constant frame rate matching the GIF, under 3 MB. Name it `<gif name>.mp4`.
   - Export a WebM (VP9) version under 3 MB with the same name and the `.webm` extension.
   - Export a still fallback from the final frame as `<gif name>-still.jpg`, and a poster from the first frame as `<gif name>-poster.jpg`.
   - Keep the original GIF and upload it too if it is under 9 MB.
   - Upload everything to `Renderings & Process`.
6. **Sources.** Leave the reference PDFs in `Sources/` out of the image folders. Upload `LA-CEC Room 98 Vendor Partner Guidance for Photo and Video Use.pdf` to `Project Information` if it is not already there. Do not publish it.
7. **Manifest.** Create `Room 98 upload manifest.md` in the hub root listing every uploaded file: filename, folder, pixel dimensions, size in KB, Drive file id, and whether it is an original, a web copy, a rendering, a plan, a diagram or a motion file.

## Checks before finishing
- Every uploaded file is under 10 MB and opens in Drive.
- Each photo is either the original or a clearly named `-web` copy. None is upscaled.
- Each GIF has an MP4, a WebM, a still and a poster, and the videos loop without a visible jump.
- The manifest lists every file.

## Do not
- Do not edit, colour-grade or crop any photograph.
- Do not mix renderings into the Photography folder.
- Do not rename files except to add `-web`, `-still` or `-poster`.

When finished, tell Jamel the manifest file name so the website team can import the images.
