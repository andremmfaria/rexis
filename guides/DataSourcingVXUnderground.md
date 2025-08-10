# VX‑Underground → URL Collection → Download → Ingest (Rexis)

This guide shows how to **collect signed PDF URLs in the browser**, save them to a `.txt`, then **download** and **ingest** the PDFs into your RAG datastore.

> Why this flow? VX‑Underground sits behind Cloudflare and serves **time‑limited signed Backblaze B2 links**. Collecting URLs inside a *real browser session* avoids bot challenges; downloading happens locally afterward.

---

## What you’ll do

1. **Open VX‑Underground** in your browser (Chrome/Firefox/Edge).
2. **Run one of the scripts below** in the DevTools Console to **save a `.txt` of PDF URLs**:
   - **Year page walker** → collects from every APT’s `Paper/` page.
   - **Single Paper page** → collects just that folder’s PDFs.
3. **Use your downloader** (`download_from_url_list.sh`) to fetch the files to disk.
4. **Ingest** with `rexis ingest file -t pdf ...`.

---

## 1) Collect URLs (Batch, from a *Year* page)

Use this on a page like:  
`https://vx-underground.org/APTs/2012/`

It **navigates the UI** (no `fetch`), visits each APT → `Paper/`, scrapes PDF links from the DOM, then **saves** them into a TXT.

```javascript
(async () => {
  const sleep = (ms) => new Promise(r => setTimeout(r, ms));
  const jitter = (min=120, max=320) => Math.floor(min + Math.random()*(max-min)); // tighter for speed
  const PDF_RX = /\.pdf(\?|$)/i;
  const CONCURRENCY = 5;  // tweak 3–8 depending on your browser/connection

  const waitFor = async (predicate, timeoutMs = 15000, step = 120) => {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      try { if (await predicate()) return true; } catch {}
      await sleep(step);
    }
    return false; // don't throw; keep going
  };

  const tiles = () => [...document.querySelectorAll('#file-display [phx-click]')];

  const clickTileByText = async (contains) => {
    const el = tiles().find(t => (t.innerText||'').trim().toLowerCase().includes(contains.toLowerCase()));
    if (!el) return false;
    el.scrollIntoView({behavior:'smooth', block:'center'});
    el.click();
    return true;
  };

  const inFolderNamed = (name) => {
    const bc = document.querySelectorAll('#breadcrumbs span');
    const last = bc[bc.length - 1];
    return last && (last.textContent || '').trim().toLowerCase() === name.toLowerCase();
  };

  const year = (location.pathname.match(/APTs\/(\d{4})\/?/i)||[])[1] || 'YEAR';
  const aptNames = tiles().map(t => (t.innerText||'').trim()).filter(Boolean);
  if (!aptNames.length) { alert('No APT tiles found'); return; }
  console.log(`[Collector] ${aptNames.length} APT entries for ${year}`);

  // 1) Collect all signed PDF URLs first (fast sweep)
  const collected = new Set();
  let visited = 0;

  for (const apt of aptNames) {
    try {
      if (!(await clickTileByText(apt))) continue;
      await waitFor(() => {
        const spans = [...document.querySelectorAll('#breadcrumbs span')].map(s => (s.textContent||'').trim());
        return spans.some(s => s === apt);
      }, 12000);

      if (!(await clickTileByText('Paper'))) {
        console.log('No Paper/ for', apt);
        history.back(); await sleep(jitter());
        continue;
      }
      await waitFor(() => inFolderNamed('paper'), 10000);

      const links = [...document.querySelectorAll('#file-display a[href]')]
        .map(a => a.href)
        .filter(h => PDF_RX.test(h));
      links.forEach(h => collected.add(h));
      visited++;

      // back to APT, then back to year
      history.back(); await sleep(jitter());
      history.back(); await sleep(jitter());
      await waitFor(() => tiles().length >= aptNames.length, 10000);

    } catch (e) {
      console.warn('Error collecting for', apt, e);
      try { history.go(-2); } catch {}
      await sleep(jitter(400, 800));
    }
    await sleep(jitter(80, 160));
  }

  const urls = [...collected];
  console.log(`[Collector] Visited ${visited} APTs. Total PDFs found: ${urls.length}`);
  if (!urls.length) { alert('No PDFs found across Paper pages.'); return; }

  // 2) Download with a small concurrency pool (anchor-click fallback)
  const triggerDownload = (url, filenameHint="") => {
    const a = document.createElement('a');
    a.href = url;
    a.download = filenameHint;   // hint only; cross-origin may ignore
    a.rel = 'noopener';
    a.target = '_blank';         // helps avoid popup blockers
    document.body.appendChild(a);
    a.click();
    a.remove();
  };

  const decodeFilename = (u) => {
    try { return decodeURIComponent(new URL(u).pathname.split('/').pop() || 'download.pdf'); }
    catch { return 'download.pdf'; }
  };

  let idx = 0, done = 0;
  const total = urls.length;

  const worker = async (id) => {
    while (true) {
      const i = idx++;
      if (i >= total) break;
      const url = urls[i];
      try {
        console.log(`Worker ${id} spawned with ${url}`)
        triggerDownload(url, decodeFilename(url));
        done++;
      } catch (e) {
        console.warn(`Worker ${id} failed on ${url}`, e);
      }
      await sleep(jitter(180, 380)); // small pacing per click
    }
  };

  const workers = Array.from({length: CONCURRENCY}, (_, i) => worker(i+1));
  await Promise.all(workers);

  console.log(`[Downloader] Triggered ${done}/${total} downloads with concurrency=${CONCURRENCY}.`);
  console.log('If some opened inline, enable “Download PDFs instead of opening” in your browser and re-run just for those entries.');
})();
```

**How to run it**

1. Open the year page (e.g. `/APTs/2012/`).
2. Press **F12 → Console**.
3. Paste the script → **Enter**.
4. A file like `vxu_2012_pdf_urls_<timestamp>.txt` will download (usually to your **Downloads** folder).

---

## 2) Collect URLs (Single, from a *Paper* page)

Use this on a page like:
`https://vx-underground.org/APTs/2012/2012.02.29 - The Sin Digoo Affair/Paper/`

It saves just that folder’s PDF links into a TXT.

```javascript
(() => {
  const PDF_RX = /\.pdf(\?|$)/i;
  const CONCURRENCY = 5;

  const anchors = [...document.querySelectorAll('#file-display a[href]')];
  const urls = anchors.map(a => a.href).filter(h => PDF_RX.test(h));
  if (!urls.length) { alert('No PDFs found on this Paper page.'); return; }

  const triggerDownload = (url, filenameHint="") => {
    const a = document.createElement('a');
    a.href = url;
    a.download = filenameHint;
    a.rel = 'noopener';
    a.target = '_blank';
    document.body.appendChild(a);
    a.click();
    a.remove();
  };

  const decodeFilename = (u) => {
    try { return decodeURIComponent(new URL(u).pathname.split('/').pop() || 'download.pdf'); }
    catch { return 'download.pdf'; }
  };

  const sleep = (ms) => new Promise(r => setTimeout(r, ms));
  const jitter = (min=120, max=320) => Math.floor(min + Math.random()*(max-min));

  let idx = 0, done = 0;
  const total = urls.length;

  const worker = async (id) => {
    while (true) {
      const i = idx++;
      if (i >= total) break;
      const url = urls[i];
      try {
        triggerDownload(url, decodeFilename(url));
        done++;
      } catch (e) {
        console.warn(`Worker ${id} failed on ${url}`, e);
      }
      await sleep(jitter());
    }
  };

  (async () => {
    const workers = Array.from({length: CONCURRENCY}, (_, i) => worker(i+1));
    await Promise.all(workers);
    console.log(`[Downloader] Triggered ${done}/${total} downloads (concurrency=${CONCURRENCY}).`);
    console.log('If some opened inline, enable your browser’s “Download PDFs” setting and retry.');
  })();
})();
```

**How to run it**

1. Open the target **Paper** page.
2. **F12 → Console**.
3. Paste → **Enter**.
4. A file like `2012_The_Sin_Digoo_Affair_pdf_urls.txt` will download.

---

## 3) Download the PDFs

You already saved the Bash downloader as `download_from_url_list.sh`. Use it like:

```bash
./download_from_url_list.sh /path/to/vxu_2012_pdf_urls_<timestamp>.txt /path/to/output_dir
```

* The script retries transient failures, resumes partial downloads, and logs successes/failures.
* **Important:** these are *signed* URLs and typically expire within **\~1 hour** of collection. If you see `403 Forbidden`, regenerate a fresh URL list and re-run the downloader quickly.

---

## 4) Ingest the PDFs with Rexis

Once downloaded:

```bash
# Batch (folder)
rexis ingest file -t pdf -d /path/to/output_dir -b 50 -m source=vxu year=2012

# Single file
rexis ingest file -t pdf -f /path/to/output_dir/<some_file>.pdf -m source=vxu year=2012
```

* Your PDF handler extracts text with PyMuPDF, wraps it as JSON, and indexes via Haystack.
* Document IDs are computed from **file content SHA‑256** (so duplicates across folders/sources dedupe cleanly).

---

## Tips & Troubleshooting

* **Keep the browser tab focused** while the batch script runs (some browsers throttle background tabs).
* If the year page has a lot of entries, you can run the batch collector multiple times with short date‑ranges (e.g., 2012 Q1/Q2) by editing the list of tiles (or stopping early).
* If downloads **open in a viewer** instead of saving:

  * That’s fine here because we’re saving **URLs**, not downloading in the browser.
  * The actual download happens with the Bash script.
* Consider organizing outputs like:

  ```
  datasets/
    vxu/
      2012/
        url_lists/
          vxu_2012_pdf_urls_2025-08-09T23-12-34Z.txt
        pdfs/
          ...
  ```
