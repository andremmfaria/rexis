# VX‑Underground -> URL Collection -> Download -> Ingest (Rexis)

This guide shows how to use your browser to **collect signed PDF links and trigger downloads** from VX‑Underground, then **ingest** the PDFs into your RAG datastore.

> Why this flow? VX‑Underground sits behind Cloudflare and serves **time‑limited signed Backblaze B2 links**. Collecting links and downloading inside a *real browser session* avoids bot challenges; the files land locally and are ready for ingest.

> See also: the ingestion companion guide — `guides/IngestVXUnderground.md`.

---

## What you’ll do

1. **Open VX‑Underground** in your browser (Chrome/Firefox/Edge).
2. **Run one of the scripts below** in the DevTools Console to **collect PDF links and trigger downloads**:
   - **Year page walker** -> collects from every APT’s `Paper/` page.
   - **Single Paper page** -> collects just that folder’s PDFs.
3. **Ingest** with `rexis ingest file -t pdf -d ./files ...`.

---

## 1) Collect & Download (Batch, from a *Year* page)

Use this on a page like: `https://vx-underground.org/APTs/2012/`

It **navigates the UI**, visits each APT -> `Paper/`, scrapes PDF links from the DOM, then **buffers** them and periodically **flushes as downloads** to avoid overwhelming the browser.

```javascript
(async () => {
  /***********************
   * CONFIG + CONSTANTS  *
   ***********************/
  const PDF_RX = /\.pdf(\?|$)/i;       // case-insensitive .pdf/.PDF
  const WAIT_TIMEOUT = 16000;          // ms
  const STEP_DELAY   = [140, 260];     // ms between UI actions during walk
  const DL_CONCURRENCY = 5;            // download 5 at a time
  const BUFFER_PERCENT = 0.20;         // buffer ≈ 20% of total discovered so far
  const MIN_BUFFER = 10;               // never buffer less than this before flushing
  const LIMIT_FIRST_N = 0;             // 0 = all APTs; otherwise first N

  /************
   * HELPERS  *
   ************/
  const sleep  = (ms) => new Promise(r => setTimeout(r, ms));
  const jitter = (a, b) => Math.floor(a + Math.random()*(b-a));
  const now    = () => new Date().toISOString();
  const norm   = (s) => (s || '').trim().replace(/\s+/g, ' ');

  const breadcrumbSpans = () => [...document.querySelectorAll('#breadcrumbs span')];
  const bcTexts = () => breadcrumbSpans().map(n => norm(n.textContent));
  const lastBC  = () => (bcTexts().slice(-1)[0] || '');

  const tiles = () => [...document.querySelectorAll('#file-display [phx-click]')];

  const parsePathFromPhx = (el) => {
    const raw = el.getAttribute('phx-click') || '';
    const m = raw.match(/"value"\s*:\s*"([^"]+)"/);
    return m ? m[1] : null;
  };

  const waitFor = async (pred, label, to=WAIT_TIMEOUT, step=150) => {
    const start = Date.now();
    while (Date.now() - start < to) {
      try { if (await pred()) return true; } catch {}
      await sleep(step);
    }
    console.warn(`[${now()}] waitFor timeout: ${label}`);
    return false;
  };

  const atYearView = (YEAR) => {
    const b = bcTexts();
    return b.length >= 2 && b[b.length-1] === YEAR && b[b.length-2] === 'APTs';
  };

  const ensureYearView = async (YEAR) => {
    if (atYearView(YEAR)) return true;

    // Try clicking breadcrumb "APTs" then YEAR tile by exact path
    const bc = breadcrumbSpans();
    const apTsCrumb = bc.find(n => norm(n.textContent) === 'APTs');
    if (apTsCrumb) {
      console.log('[nav] Clicking breadcrumb: APTs');
      apTsCrumb.click();
      await waitFor(() => bcTexts().slice(-1)[0] === 'APTs', 'breadcrumb APTs');
      await sleep(jitter(...STEP_DELAY));
    }

    const yearTile = tiles().find(el => parsePathFromPhx(el) === `APTs/${YEAR}/`);
    if (yearTile) {
      console.log(`[nav] Entering YEAR via tile path: APTs/${YEAR}/`);
      yearTile.click();
      await waitFor(() => atYearView(YEAR), `enter YEAR ${YEAR}`);
      await sleep(jitter(...STEP_DELAY));
      return true;
    }

    console.warn('[nav] Could not re-enter year via LiveView; staying put.');
    return atYearView(YEAR);
  };

  const clickTileByPath = async (path) => {
    const el = tiles().find(t => parsePathFromPhx(t) === path);
    if (!el) return false;
    el.scrollIntoView({behavior:'smooth', block:'center'});
    el.click();
    return true;
  };

  const inPathTail = (path) => {
    const tail = path.split('/').filter(Boolean).pop() + '/';
    return (lastBC().toLowerCase() === tail.slice(0, -1).toLowerCase());
  };

  const decodeFilename = (u) => {
    try { return decodeURIComponent(new URL(u).pathname.split('/').pop() || 'download.pdf'); }
    catch { return 'download.pdf'; }
  };

  const triggerDownload = (url, filenameHint="") => {
    const a = document.createElement('a');
    a.href = url;
    a.download = filenameHint;   // hint; cross-origin may ignore
    a.rel = 'noopener';
    a.target = '_blank';         // helps with popup policies
    document.body.appendChild(a);
    a.click();
    a.remove();
  };

  /***********************
   * YEAR / ENTRY SETUP  *
   ***********************/
  const yearMatch = location.pathname.match(/APTs\/(\d{4})\/?/i);
  const YEAR = yearMatch ? yearMatch[1] : null;
  if (!YEAR) { alert('Not on an APT year page. Navigate to /APTs/<year>/ first.'); return; }

  console.group(`[Batch+Buffer Downloader] YEAR ${YEAR} @ ${now()}`);
  console.log('Page URL:', location.href);

  const rawTiles = tiles();
  const entries = rawTiles.map(el => ({
      title: norm(el.innerText),
      path:  parsePathFromPhx(el)
    }))
    .filter(e => e.path && e.path.startsWith(`APTs/${YEAR}/`) && /\/$/.test(e.path))
    .filter((e, i, arr) => arr.findIndex(x => x.path === e.path) === i); // de-dupe by path

  console.log(`Found ${entries.length} APT entries (by path).`);
  console.table(entries.map((e, i) => ({ idx: i, path: e.path, title: e.title })));

  const work = LIMIT_FIRST_N > 0 ? entries.slice(0, LIMIT_FIRST_N) : entries;

  /***********************
   * BUFFER + DOWNLOADS  *
   ***********************/
  let totalDiscovered = 0;     // all PDFs we have seen (including flushed)
  let totalTriggered  = 0;     // all clicks actually issued
  let buffer = [];             // pending URLs to download
  let flushCount = 0;

  const currentBufferTarget = () => Math.max(MIN_BUFFER, Math.ceil(totalDiscovered * BUFFER_PERCENT));

  const flushBuffer = async () => {
    if (!buffer.length) return;
    flushCount++;
    const urls = buffer.slice(); // copy
    buffer = [];                 // clear before fire (so we can keep collecting)
    const target = urls.length;
    console.group(`[flush#${flushCount}] Triggering ${target} downloads (concurrency=${DL_CONCURRENCY})`);
    console.table(urls.map((u, i) => ({ i, filename: decodeFilename(u), url: u })));

    let idx = 0;
    const worker = async (id) => {
      while (true) {
        const i = idx++;
        if (i >= target) break;
        const url = urls[i];
        try {
          triggerDownload(url, decodeFilename(url));
          totalTriggered++;
        } catch (e) {
          console.warn(`Worker ${id} failed on ${url}`, e);
        }
        await sleep(jitter(150, 300));
      }
    };
    const workers = Array.from({length: DL_CONCURRENCY}, (_, i) => worker(i+1));
    await Promise.all(workers);
    console.log(`[flush#${flushCount}] Done. Total triggered so far: ${totalTriggered}`);
    console.groupEnd();
  };

  /*****************
   * WALK & COLLECT *
   *****************/
  const perAPT = [];
  for (let i = 0; i < work.length; i++) {
    const { title, path } = work[i];
    const aptLog = {
      idx: i+1, total: work.length,
      title, path,
      enteredAPT: false,
      paperPath: path + 'Paper/',
      paperEntered: false,
      anchorCount: 0,
      pdfCount: 0,
      urls: [],
      errors: []
    };

    console.group(`APT [${i+1}/${work.length}] - ${title}`);
    console.log('APT path:', path);

    try {
      // Ensure we’re at YEAR listing
      const okYear = await ensureYearView(YEAR);
      console.log('ensureYearView():', okYear, 'breadcrumbs:', bcTexts());
      if (!okYear) aptLog.errors.push('Failed to reach YEAR view');

      // Enter APT by exact path
      const clickedAPT = await clickTileByPath(path);
      console.log('clickTileByPath -> APT:', clickedAPT);
      if (!clickedAPT) {
        aptLog.errors.push('APT tile not found by path');
        perAPT.push(aptLog); console.groupEnd(); continue;
      }
      await waitFor(() => inPathTail(path), `enter APT ${path}`);
      aptLog.enteredAPT = true;
      console.log('Entered APT (breadcrumbs):', bcTexts());
      await sleep(jitter(...STEP_DELAY));

      // Enter Paper/ (prefer path; fallback to text)
      let clickedPaper = await clickTileByPath(aptLog.paperPath);
      console.log('clickTileByPath -> Paper:', clickedPaper, 'target:', aptLog.paperPath);
      if (!clickedPaper) {
        const paperTextTile = tiles().find(t => norm(t.innerText).toLowerCase() === 'paper');
        if (paperTextTile) {
          console.log('Fallback: clicking Paper by text');
          paperTextTile.click();
          clickedPaper = true;
        }
      }
      if (!clickedPaper) {
        console.warn('No Paper/ for this APT.');
        aptLog.errors.push('No Paper/ tile');
        await ensureYearView(YEAR);
        perAPT.push(aptLog); console.groupEnd(); continue;
      }

      await waitFor(() => lastBC().toLowerCase() === 'paper', 'enter Paper/', 12000);
      aptLog.paperEntered = true;
      console.log('Entered Paper/ (breadcrumbs):', bcTexts());
      await sleep(jitter(...STEP_DELAY));

      // Collect PDF links (case-insensitive)
      const anchors = [...document.querySelectorAll('#file-display a[href]')];
      const hrefs   = anchors.map(a => a.href).filter(Boolean);
      const pdfs    = hrefs.filter(h => PDF_RX.test(h));

      aptLog.anchorCount = anchors.length;
      aptLog.pdfCount    = pdfs.length;
      aptLog.urls        = pdfs;

      console.log(`Anchors total: ${anchors.length} | PDFs detected: ${pdfs.length}`);
      if (pdfs.length) {
        console.table(pdfs.map((u, k) => ({
          i: k, filename: decodeFilename(u), url: u
        })));
      } else {
        console.warn('No PDFs found in this Paper/.');
      }

      // Push into buffer and maybe flush
      totalDiscovered += pdfs.length;
      buffer.push(...pdfs);
      const targetBuf = currentBufferTarget();
      console.log(`Buffer: ${buffer.length} items | target ≈ ${targetBuf} (20% of ${totalDiscovered}, min ${MIN_BUFFER})`);

      if (buffer.length >= targetBuf) {
        await flushBuffer();
      }

      // Return to YEAR deterministically
      const okBack = await ensureYearView(YEAR);
      console.log('Back to YEAR:', okBack, 'breadcrumbs:', bcTexts());

    } catch (e) {
      console.error('Exception during APT walk:', e);
      aptLog.errors.push(String(e && e.message ? e.message : e));
      await ensureYearView(YEAR);
    }

    perAPT.push(aptLog);
    console.groupEnd();
    await sleep(jitter(...STEP_DELAY));
  }

  /*****************
   * FINAL FLUSH   *
   *****************/
  if (buffer.length) {
    console.log(`[final] Flushing remaining ${buffer.length} URL(s) in buffer...`);
    await flushBuffer();
  }

  /*****************
   * SUMMARY       *
   *****************/
  console.group(`[Summary ${YEAR}]`);
  console.log(`Total URLs discovered: ${totalDiscovered}`);
  console.log(`Total downloads triggered: ${totalTriggered}`);
  console.table(perAPT.map(x => ({
    idx: x.idx, pdfs: x.pdfCount, entered: x.enteredAPT, paper: x.paperEntered,
    title: x.title, path: x.path, errors: x.errors.join(' | ')
  })));
  console.groupEnd();

  // Expose debug object
  window.__vxuBatch = { YEAR, entries: work, perAPT, totalDiscovered, totalTriggered, flushCount };
  console.log('Debug object available at window.__vxuBatch');
  console.groupEnd(); // Batch+Buffer Downloader
})();
```

**How to run it**

1. Open the year page (e.g. `/APTs/2012/`).
2. Press **F12 -> Console**.
3. Paste the script -> **Enter**.
4. The apt files will be downloaded to your computer (probably on the Downloads folder)

---

## 2) Collect & Download (Single, from a *Paper* page)

Use this on a page like: `https://vx-underground.org/APTs/2012/2012.02.29 - The Sin Digoo Affair/Paper/`

It collects just that folder’s PDFs and triggers their download.

```javascript
(async () => {
  /***********************
   * CONFIG + CONSTANTS  *
   ***********************/
  const PDF_RX = /\.pdf(\?|$)/i;     // case-insensitive .pdf/.PDF
  const WAIT_TIMEOUT = 15000;        // ms
  const STEP_DELAY   = [120, 240];   // ms between UI steps
  const DL_CONCURRENCY = 5;          // download N at a time
  const BUFFER_PERCENT = 0.20;       // buffer ≈ 20% of total URLs
  const MIN_BUFFER = 10;             // at least this many before flushing

  /************
   * HELPERS  *
   ************/
  const sleep  = (ms) => new Promise(r => setTimeout(r, ms));
  const jitter = (a, b) => Math.floor(a + Math.random()*(b-a));
  const now    = () => new Date().toISOString();
  const norm   = (s) => (s || '').trim().replace(/\s+/g, ' ');

  const breadcrumbSpans = () => [...document.querySelectorAll('#breadcrumbs span')];
  const bcTexts = () => breadcrumbSpans().map(n => norm(n.textContent));
  const lastBC  = () => (bcTexts().slice(-1)[0] || '');

  const tiles = () => [...document.querySelectorAll('#file-display [phx-click]')];
  const parsePathFromPhx = (el) => {
    const raw = el.getAttribute('phx-click') || '';
    const m = raw.match(/"value"\s*:\s*"([^"]+)"/);
    return m ? m[1] : null;
  };

  const waitFor = async (pred, label, to=WAIT_TIMEOUT, step=140) => {
    const start = Date.now();
    while (Date.now() - start < to) {
      try { if (await pred()) return true; } catch {}
      await sleep(step);
    }
    console.warn(`[${now()}] waitFor timeout: ${label}`);
    return false;
  };

  const clickTileByPath = async (path) => {
    const el = tiles().find(t => parsePathFromPhx(t) === path);
    if (!el) return false;
    el.scrollIntoView({behavior:'smooth', block:'center'});
    el.click();
    return true;
  };

  const decodeFilename = (u) => {
    try { return decodeURIComponent(new URL(u).pathname.split('/').pop() || 'download.pdf'); }
    catch { return 'download.pdf'; }
  };

  // Cross-origin safe download trigger (no fetch -> no CORS)
  const triggerDownload = (url, filenameHint="") => {
    const a = document.createElement('a');
    a.href = url;
    a.download = filenameHint; // may be ignored cross-origin, but helps
    a.rel = 'noopener';
    a.target = '_blank';       // friendlier to popup blockers
    document.body.appendChild(a);
    a.click();
    a.remove();
  };

  /***********************
   * CONTEXT + NAV       *
   ***********************/
  console.group(`[Single-APT Collector+Downloader] @ ${now()}`);
  console.log('Page URL:', location.href);
  console.log('Breadcrumbs at start:', bcTexts());

  // Determine if we are already in Paper/, otherwise find Paper/ path from tiles
  let paperPath = null;
  const isAtPaper = lastBC().toLowerCase() === 'paper';

  if (isAtPaper) {
    console.log('Detected we are already inside Paper/.');
  } else {
    // We are likely on the APT root. Locate the Paper/ tile and take its path.
    const paperTile = tiles().find(t => norm(t.innerText).toLowerCase() === 'paper' || /paper\/"?]?\]?$/i.test(parsePathFromPhx(t) || ''));
    if (!paperTile) {
      console.warn('No Paper/ tile found on this APT page. Aborting.');
      console.groupEnd();
      return;
    }
    paperPath = parsePathFromPhx(paperTile);
    console.log('Resolved Paper/ path:', paperPath);

    // Enter Paper/ via path (preferred)
    const clicked = await clickTileByPath(paperPath);
    console.log('clickTileByPath(Paper):', clicked);
    if (!clicked) {
      console.warn('Could not click Paper/ by path; trying tile click directly.');
      paperTile.scrollIntoView({behavior:'smooth', block:'center'});
      paperTile.click();
    }

    await waitFor(() => lastBC().toLowerCase() === 'paper', 'enter Paper/');
    console.log('Breadcrumbs after entering Paper/:', bcTexts());
    await sleep(jitter(...STEP_DELAY));
  }

  /***********************
   * COLLECT PDF URLS    *
   ***********************/
  const anchors = [...document.querySelectorAll('#file-display a[href]')];
  const hrefs   = anchors.map(a => a.href).filter(Boolean);
  const urls    = hrefs.filter(h => PDF_RX.test(h));

  console.log(`Anchors on Paper/: ${anchors.length}`);
  console.log(`PDFs detected (case-insensitive): ${urls.length}`);

  if (!urls.length) {
    console.warn('No PDFs found in this Paper/. Nothing to download.');
    console.groupEnd();
    return;
  }

  console.table(urls.map((u, i) => ({ i, filename: decodeFilename(u), url: u })));

  /***********************
   * BUFFERED DOWNLOADS  *
   ***********************/
  const total = urls.length;
  const targetBuffer = Math.max(MIN_BUFFER, Math.ceil(total * BUFFER_PERCENT));
  console.log(`Total URLs: ${total} | Buffer target ≈ ${targetBuffer} (20% of total, min ${MIN_BUFFER}) | Concurrency=${DL_CONCURRENCY}`);

  let buffer = [];
  let totalTriggered = 0;
  let flushCount = 0;

  const flushBuffer = async () => {
    if (!buffer.length) return;
    flushCount++;
    const toFlush = buffer.slice();
    buffer = [];

    console.group(`[flush#${flushCount}] Triggering ${toFlush.length} downloads (concurrency=${DL_CONCURRENCY})`);
    console.table(toFlush.map((u, i) => ({ i, filename: decodeFilename(u), url: u })));

    let idx = 0;
    const worker = async (id) => {
      while (true) {
        const i = idx++;
        if (i >= toFlush.length) break;
        const url = toFlush[i];
        try {
          triggerDownload(url, decodeFilename(url));
          totalTriggered++;
        } catch (e) {
          console.warn(`Worker ${id} failed on ${url}`, e);
        }
        await sleep(jitter(150, 300));
      }
    };

    const workers = Array.from({length: DL_CONCURRENCY}, (_, i) => worker(i+1));
    await Promise.all(workers);

    console.log(`[flush#${flushCount}] Done. Total triggered so far: ${totalTriggered}`);
    console.groupEnd();
  };

  // Fill buffer and flush whenever threshold is reached
  for (let i = 0; i < urls.length; i++) {
    buffer.push(urls[i]);
    if (buffer.length >= targetBuffer) {
      console.log(`Buffer filled (${buffer.length} >= ${targetBuffer}). Flushing...`);
      await flushBuffer();
      await sleep(jitter(...STEP_DELAY));
    }
  }

  // Final flush if anything remains
  if (buffer.length) {
    console.log(`[final] Flushing remaining ${buffer.length} URL(s) in buffer...`);
    await flushBuffer();
  }

  /***********************
   * SUMMARY + EXPORT    *
   ***********************/
  console.group(`[Summary]`);
  console.log(`Total URLs discovered: ${total}`);
  console.log(`Total downloads triggered: ${totalTriggered}`);
  console.groupEnd();

  // Expose debug object for inspection
  window.__vxuSingle = {
    pageURL: location.href,
    breadcrumbs: bcTexts(),
    total,
    totalTriggered,
    bufferPercent: BUFFER_PERCENT,
    minBuffer: MIN_BUFFER,
    targetBuffer,
    flushCount
  };
  console.log('Debug object available at window.__vxuSingle');
  console.groupEnd(); // Single-APT Collector+Downloader
})();
```

**How to run it**

1. Open the target **Paper** page.
2. **F12 -> Console**.
3. Paste -> **Enter**.
4. The target apt file will be downloaded on your computer (probably on the Downloads folder)

---

## 3) Ingest the PDFs with Rexis

Once downloaded:

```bash
# Batch (folder)
rexis ingest file -t pdf -d /path/to/output_dir -b 50 -m source=vxu year=2012

# Single file
rexis ingest file -t pdf -f /path/to/output_dir/<some_file>.pdf -m source=vxu year=2012
```

* Your PDF handler extracts text with PyMuPDF, wraps it as JSON, and indexes via Haystack.
* Document IDs are computed from **file content SHA‑256** (so duplicates across folders/sources dedupe cleanly).

For a deeper walkthrough of CLI options, metadata, batching, and how deduplication works under the hood, see `guides/IngestVXUnderground.md`.

---

## Tips & Troubleshooting

* **Keep the browser tab focused** while the batch script runs (some browsers throttle background tabs).
* If the year page has a lot of entries, you can run the batch collector multiple times with short date‑ranges (e.g., 2012 Q1/Q2) by editing the list of tiles (or stopping early).
* If downloads **open in a viewer** instead of saving: most browsers still keep a copy in the Downloads list; alternatively set your browser to “Always ask where to save files,” or right‑click -> “Save link as...”.

Optional: prefer exporting URLs only (no downloads)? Comment out the `triggerDownload(...)` calls in the scripts, inspect `window.__vxuBatch` / `window.__vxuSingle` for collected URLs, and save them as needed.
