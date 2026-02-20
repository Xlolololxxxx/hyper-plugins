# JC Deep Code Analysis For Target-Panel Engine Pipeline

Date: 2026-02-19
Scope analyzed: `ParsingGlobal/jc/jc/*`
Goal: establish JC as baseline parsing source and define first pipeline slice for integration.

## 1. What JC Is (Architecturally)

JC is a parser framework with:
- A parser registry and loader (`jc/lib.py`)
- CLI orchestration and magic command mode (`jc/cli.py`)
- Per-command parser modules (`jc/parsers/*.py`)
- Shared normalization/conversion helpers (`jc/utils.py`)
- Streaming parser helper/decorator (`jc/streaming.py`)

Your plugin should integrate with JC as a library (`import jc` / `jc.parse(...)`) rather than shelling out to the CLI for core engine behavior.

## 2. Core Runtime Path (Library)

Primary API:
- `jc.parse(parser_mod_name, data, quiet=False, raw=False, ignore_exceptions=None, **kwargs)`

Resolution flow (from `jc/lib.py`):
1. Resolve parser name variants (`--dig`, `dig`, `dig`) via name normalization.
2. Load parser module from built-ins or plugin parsers (`jcparsers.*`).
3. Validate parser has `info` and `parse` attributes.
4. Call parser `parse()` with arguments.

Important behaviors:
- If parser module import fails, JC can load `disabled_parser` and warn.
- `raw=True` preserves raw schema values (less type coercion).
- `quiet=True` suppresses compatibility warning chatter.

## 3. Parser Module Contract

Each parser module generally exposes:
- `class info`: metadata
  - `description`, `compatible`, `magic_commands`, `tags`, `version`
- `parse(data, quiet=False, raw=False, ...)`

Many parsers follow pattern:
- internal extraction/parsing functions
- `_process()` phase for type conversions
- `raw` bypasses conversion logic where applicable

Implication for us:
- We can standardize ingestion with a thin JC runner because parser entry points are consistent.

## 4. Streaming vs Standard Parsers

Streaming helpers in `jc/streaming.py` add:
- type checks for iterable line input
- `ignore_exceptions` option that yields metadata (`_jc_meta`) instead of hard failing

For initial target-panel use:
- Treat selected parsers (`dig`, `ping`, `traceroute`, `curl_head`) as standard parse calls first.
- Add streaming mode later if needed for very long outputs.

## 5. Plugin/Override Extension Model In JC

`jc/lib.py` supports local parser overrides/plugins from user data dir:
- `~/.local/share/jc/jcparsers` equivalent via `appdirs`
- plugin parser name merges into parser list

This gives us two strategy choices:
1. Keep your custom recon parser logic outside JC and map JC JSON into plugin model.
2. Write true JC-compatible custom parsers and load through JC plugin mechanism.

Given your direction (“modify JC if needed”), option 2 is fully aligned long-term.

## 6. Coverage Reality For Current Sidebar Commands

Current external sidebar tools: 31
Clearly covered by existing JC parser modules: 4 parser families used now (`curl_head`, `dig`, `ping`, `traceroute`), mapped to your relevant commands.
Most recon tools (`nmap`, `gobuster`, `nikto`, `nuclei`, `ffuf`, `sqlmap`, etc.) are not first-class JC built-ins and will require custom JC parsers or adapter strategy.

Conclusion:
- JC baseline rollout should begin with the covered set (done in corpus generation).
- Unsupported recon tools should be planned as custom JC parser modules, not ad-hoc regex in plugin, if you want parser logic centralized.

## 7. Baseline Corpus Created

Location:
- `local/hyper-target-panel/data/jc-baseline/`

Contents:
- `curl_head` 5 cases
- `dig` 5 cases
- `ping` 5 cases
- `traceroute` 5 cases

Each case includes:
- `raw.out` (original command output fixture)
- `parsed.json` (JC structured output)
- `meta.json` (parser/tool/source fixture metadata)

This is now your ground-truth sample corpus for UI work.

## 8. Recommended First Pipeline Slice (Implementation Part 1)

Objective:
- Add a JC ingestion path without replacing existing parser-dependent UI behavior yet.

Steps:
1. Add `JcRunner` module in plugin:
   - input: parser name + raw output
   - output: raw JC JSON + parse metadata
2. Add `JcRegistry` mapping for covered tools:
   - `curl-headers`, `curl-full` -> `curl_head`
   - `dig-*` -> `dig`
   - `ping` -> `ping`
   - `traceroute` -> `traceroute`
3. Update `OutputProcessor` to dual-write for covered tools:
   - continue existing model updates
   - additionally store raw JC JSON blobs per run
4. Store raw JC JSON under plugin data path with run IDs.
5. Add snapshot tests against `jc-baseline` corpus to guarantee stability.

Do not do in Part 1:
- Full UI migration to JC schema
- Full parser replacement for unsupported recon commands
- Streaming parser complexity

## 9. Risks And Controls

Risks:
- Schema differences between parser outputs and current UI assumptions.
- Potential parser behavior changes if JC version updates.
- Runtime overhead if parsing huge outputs synchronously.

Controls:
- Pin local JC version used by integration path.
- Keep corpus-based regression snapshots.
- Record parser version in each stored result metadata.
- Add parser timeout/size guardrails later.

## 10. Practical Decision For Next Turn

Before coding the engine pipeline part 1, lock these:
1. Canonical raw storage format: JSON document per run vs NDJSON stream.
2. Migration behavior for existing run data.
3. Whether `raw=True` or processed JC types should be canonical baseline.

Recommended baseline setting:
- Canonical = processed JC output (`raw=False`) for cleaner downstream use.
- Also store parser metadata (`parser`, `jc_version`, timestamp, tool_id, command).
