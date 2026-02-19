# Spec: Recon Improvements and CI Setup

## Summary
Add missing features (API recon pipeline, HTML reporting), setup CI, and initialize documentation structure.

## Goals
- Add "API Recon" and "Full Recon" pipeline templates.
- Add HTML export capability to `hyper-findings-log`.
- Setup GitHub Actions CI workflow.
- Ensure proper tracking of tasks and changes.

## Non-goals
- Major refactoring of existing plugins.
- Replacing existing tools (only adding templates).

## User Flows
- User selects "API Recon" in pipeline tab -> Pipeline executes -> Findings logged.
- User clicks "Export HTML" in findings tab -> HTML report generated.
- Push to repo -> CI workflow runs.

## Edge Cases
- Missing tools for new pipelines (will fail gracefully or skip).
- Large number of findings in HTML export (should handle reasonably).

## Acceptance Criteria
- New pipeline templates visible in UI.
- HTML export generates valid HTML file.
- CI workflow passes (or attempts to run).
