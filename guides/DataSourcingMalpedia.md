## Malpedia data sourcing guide

This guide shows how to collect Malpedia references with the REXIS CLI command `rexis collect malpedia`, which uses `collect_malpedia_exec` under the hood.

### What it does

- Fetches two Malpedia datasets:
	- References index mapping URL -> families/actors
	- BibTeX dump containing title, source, date, metadata for each reference
- Cross-references both by URL and emits a JSON array of merged entries with:
	- title, source, url, date
	- families: [{ id, common_name }]
	- actors: [{ id, common_name }]
	- meta: { author, language, urldate, ... }
- Applies AND filters based on your flags (all conditions must match).

### Command

```bash
rexis collect malpedia [OPTIONS]
```

### Options

- --family-id, -f: Regex-compatible pattern to match family id, common name, or alt names (e.g., `-f "^win\\."` or `-f "win.*"`).
- --actor-id, -a: Regex-compatible pattern to match actor id, common name, or alt names (e.g., `-a "^apt\\."`).
- --search-term, -s: Regex-compatible search across all metadata (title, source, url, meta fields) and names; falls back to fuzzy matching if regex doesn’t match (e.g., `-s "cobalt|fin7"`, `-s "dridex"`).
- --start-date: Inclusive start date (YYYY-MM-DD). If set without --end-date, today is assumed for end.
- --end-date: Inclusive end date (YYYY-MM-DD).
- --max: Maximum items to keep after filtering.
- --output-path, -o: Output file path (default: malpedia_urls.json).

All filters are applied with AND semantics.

### Examples

Collect Windows families references in H1 2025 and save to a file:

```bash
rexis collect malpedia -f "^win\\." \
	--start-date 2025-01-01 --end-date 2025-06-30 \
	-o data/malpedia/win_h1_2025.json
```

Filter by actor pattern and fuzzy search term:

```bash
rexis collect malpedia -a "^apt\\.(turla|sandworm)" \
	-s cobaltstrike \
	-o data/malpedia/apt_refs.json
```

Regex search across all metadata (title/source/url/meta and names):

```bash
rexis collect malpedia -s "(fin7|paperbug|qakbot)" -o data/malpedia/references.json
```

Limit number of results after filters:

```bash
rexis collect malpedia -s "^a.*" --max 200 -o data/malpedia/a_prefix_top200.json
```

No filters (latest full merge), default output:

```bash
rexis collect malpedia
```

### Output format

The output is a JSON array. Each entry looks like:

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

### Tips

- Regex vs fuzzy: `--search-term` first tries regex. If it doesn’t match anything, it falls back to fuzzy match (partial ratio) over all searchable text.
- Family/actor matching: both `--family-id` and `--actor-id` patterns match id (e.g., `win.dridex`), common_name, and alt_names.
- Date filtering: both bounds are inclusive; when only `--start-date` is provided, `--end-date` defaults to today.
- Use `jq` to inspect or post-process results:

```bash
jq '.[0:5]' data/malpedia/references.json
```

### Troubleshooting

- No results: relax your regex (e.g., use `.*`), or try only one of the filters first.
- Performance: add `--max` to cap entries; regex can be slower on large datasets.
- Networking: ensure MALPEDIA_BASE is set in config (settings.toml) if using a custom endpoint.
