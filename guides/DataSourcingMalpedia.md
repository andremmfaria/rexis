# Malpedia data sourcing guide

This guide shows how to collect Malpedia references with the REXIS CLI command `rexis collect malpedia`, which uses `collect_malpedia_exec` under the hood.

## What it does

- Fetches two Malpedia datasets:
	- References index mapping URL -> families/actors
	- BibTeX dump containing title, source, date, metadata for each reference
- Cross-references both by URL and emits a JSON array of merged entries with:
	- title, source, url, date
	- families: [{ id, common_name }] (common_name may include alt names)
	- actors: [{ id, common_name }] (common_name may include alt names)
	- meta: { author, language, urldate, ... }
- Applies AND filters based on your flags (all conditions must match).
- Writes a run report alongside the output with metrics and inputs.
- Optionally downloads and ingests referenced documents when `--ingest` is used.

## Command

```bash
rexis collect malpedia [OPTIONS]
```

## Options

- --family-id, -f: Regex-compatible pattern to match family id or name (e.g., `-f "^win\\."` or `-f "win.*"`).
- --actor-id, -a: Regex-compatible pattern to match actor id or name (e.g., `-a "^apt\\."`).
- --search-term, -s: Regex-compatible search across names and metadata (title, source, url, meta). Falls back to fuzzy match if regex doesn’t match (e.g., `-s "cobalt|fin7"`, `-s "dridex"`).
- --start-date: Inclusive start date (YYYY-MM-DD). If set without `--end-date`, today is assumed for end.
- --end-date: Inclusive end date (YYYY-MM-DD).
- --max: Maximum items to keep after filtering.
- --run-name, -n: Run name used to name the output file/folder (default: random UUID).
- --output-dir, -o: Directory to write outputs into (default: current directory).
- --ingest, -i: Download referenced documents and ingest them into the index.

All filters are applied with AND semantics.

## Examples

Collect Windows families references in H1 2025 and write outputs to a directory:

```bash
rexis collect malpedia -f "^win\\." \
	--start-date 2025-01-01 --end-date 2025-06-30 \
	-o data/malpedia
```

Filter by actor pattern and fuzzy search term:

```bash
rexis collect malpedia -a "^apt\\.(turla|sandworm)" \
	-s cobaltstrike \
	-o data/malpedia
```

Regex search across all metadata (title/source/url/meta and names):

```bash
rexis collect malpedia -s "(fin7|paperbug|qakbot)" -o data/malpedia
```

Limit number of results after filters:

```bash
rexis collect malpedia -s "^a.*" --max 200 -o data/malpedia
```

No filters (latest full merge), default output:

```bash
rexis collect malpedia
```

Download and ingest referenced documents (PDF/HTML/TEXT) after collection:

```bash
rexis collect malpedia -s cobaltstrike -i -o data/malpedia
```

## Output files and format

- The main output is a JSON array saved as `malpedia-collect-<run_name>.json` in `--output-dir`.
- A run directory named `malpedia-collect-<run_name>/` is created next to the JSON and contains a run report `<base>.report.json` with timing, inputs, and counters.

Each JSON entry looks like:

```json
{
	"title": "Threat report title",
	"url": "https://example.com/report",
	"source": "Vendor or site",
	"date": "2025-05-12",
	"families": [{ "id": "win.dridex", "common_name": "Dridex (Bugat)" }],
	"actors": [{ "id": "apt.fin7", "common_name": "FIN7 (Carbanak)" }],
	"meta": { "author": "Researcher", "language": "en", "urldate": "2025-05-13" }
}
```

### Run report

The report `<base>.report.json` captures counts like total bib entries, merged entries, filtered entries, saved entries, start/end timestamps, and the input flags.

## Tips

- Regex vs fuzzy: `--search-term` first tries regex. If it doesn’t match anything, it falls back to fuzzy match (partial ratio) over all searchable text.
- Family/actor matching: `--family-id` and `--actor-id` match id and common_name (which may include alt names inline).
- Date filtering: both bounds are inclusive; when only `--start-date` is provided, `--end-date` defaults to today.
- Ingestion: with `-i`, URLs are downloaded concurrently (up to 4 workers) with small random jitter; social-media hosts are skipped.
- Use `jq` to inspect or post-process results:

```bash
jq '.[0:5]' data/malpedia/malpedia-collect-<run_name>.json
```

## Troubleshooting

- No results: relax your regex (e.g., use `.*`), or try only one of the filters first.
- Performance: add `--max` to cap entries; regex can be slower on large datasets.
- Networking/API: the base URL comes from `config.settings.toml` → `ingestion.malpedia_base_url`.
