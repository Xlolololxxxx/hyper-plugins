# JC Full Code Scan And Agent Dispatch Plan

Date: 2026-02-20
Scope: `ParsingGlobal/jc` + `local/hyper-target-panel/config/tools.json`

## 1. Scan Results

- JC version in tree: `1.25.6` (`ParsingGlobal/jc/jc/lib.py`)
- Parser modules in `jc/parsers`: `240` python files
- Active parser modules in registry: `229`
- Test modules in upstream suite: `235`
- Magic command mappings (command -> parser): `132`

This means JC is mature and broad, but recon tooling in this plugin still requires custom adapters for most commands.

## 2. How JC Actually Works (Code Path)

- CLI path: `jc/cli.py`
  - parses flags, can run in "magic" command mode
  - renders JSON/YAML, supports slicing and metadata output
- Library path: `jc/lib.py`
  - `jc.parse(parser, data, quiet=False, raw=False, ignore_exceptions=None)`
  - resolves parser names (`dig`, `--dig`, `dig` module)
  - loads built-in parser (`jc.parsers.*`) or plugin parser (`jcparsers.*`)
- Parser contract:
  - `class info` metadata (description, tags, magic_commands, compatibility)
  - `parse(data, quiet=False, raw=False, ...)`
- Streaming support: `jc/streaming.py`
  - line-by-line parsers with `_jc_meta` error capture when `ignore_exceptions=True`

Integration implication for target-panel:
- Keep using `JcRunner` + `JcRegistry` for parser selection.
- Treat JC structured output as canonical baseline data.
- UI should adapt to that baseline, not the other way around.

## 3. Coverage Against Current Tool Catalog

Coverage file: `docs/plans/2026-02-20-jc-tool-coverage.json`

- Tools analyzed: `36`
- Covered directly by existing JC magic parsers: `3`
  - `dig_any` -> `dig`
  - `curl_headers` -> `curl_head`
  - `curl_dump_full` -> `curl_head` (header-focused parse)
- Not covered (need custom adapters/parsers): `33`
- Distinct base command families missing: `19`
  - `nmap`, `nikto`, `gobuster`, `ffuf`, `nuclei`, `sqlmap`, `whatweb`, `subfinder`, `amass`, `gau`, `katana`, `dirsearch`, `feroxbuster`, `arjun`, `dalfox`, `hydra`, `searchsploit`, `whois`, `waybackurls`

## 4. Sub-Agent Dispatch Artifacts (One Per Missing Tool)

Generated folder: `docs/agents/jc-custom/`

- Index: `docs/agents/jc-custom/README.md`
- Individual briefs: `33` files, one per tool ID

Each brief contains:
- exact tool scope and command template
- required deliverables
- acceptance criteria
- storage and registry integration targets

Example brief:
- `docs/agents/jc-custom/nmap_service.md`

## 5. Recommended Execution Order (Parser Pipeline Part 1)

High-value first wave:
1. `nmap_*`
2. `nikto`
3. `gobuster_dir`
4. `ffuf_*`
5. `nuclei_*`

Second wave:
1. `whatweb`, `whois`, `searchsploit`
2. `subfinder`, `amass_passive`, `gau_passive`, `waybackurls`
3. `katana_*`, `dirsearch`, `feroxbuster`
4. `sqlmap`, `arjun_*`, `dalfox`, `hydra_*`

Reason: first wave is your current workflow core and produces most downstream context.

## 6. Acceptance Gate For Each Agent Task

A parser task is complete only if all pass:
1. 5+ real fixtures committed under `local/hyper-target-panel/data/jc-baseline/<tool_id>/`
2. adapter parser test file exists and passes
3. `JcRegistry` routes tool ID correctly
4. `TargetStore.storeJcSnapshot(...)` receives and persists output
5. no fallback to ad-hoc regex in UI path

## 7. Immediate Next Move

Start implementation batch with 5 parallel agents from wave 1:
- `nmap_service`
- `nikto`
- `gobuster_dir`
- `ffuf_dir`
- `nuclei_url`

Then iterate pattern to sibling variants (`nmap_*`, `ffuf_*`, `nuclei_*`).
