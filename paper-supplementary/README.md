# Correlic Paper — Supplementary Artifacts

Machine-readable artifacts accompanying the paper:

**Closing the AI Agent Trust Gap: Kernel-Level Runtime Security Monitoring for AI Agents**
Ayush Mishra · Correlic · ORCID [0009-0002-3116-1969](https://orcid.org/0009-0002-3116-1969) · Technical report, 2026 ([Markdown](../backend/docs/paper/correlic-paper.md) · [PDF](../backend/docs/paper/correlic-paper.pdf))

These YAML files are referenced in the paper and released to enable independent audit of the detection engine and reproduction of the evaluation setup described in §11.

## Contents

| File | Description | Paper reference |
|---|---|---|
| [`rules.yaml`](./rules.yaml) | 13 AI-gated detection rules with MITRE ATT&CK mappings, per-signal confidence matrices, and finding-context schemas | §7, Table 3 |
| [`chains.yaml`](./chains.yaml) | 11 multi-step attack chain patterns with time windows, amplified severities, and chain-correlator behavior | §7.3, Table 4 |
| [`never_baseline.yaml`](./never_baseline.yaml) | Safety list preventing auto-baseline poisoning — file suffixes, directory patterns, exact basenames, C2 ports, anonymizing DNS suffixes, and dual-use binaries | §8.3, Appendix C |

## Format

Each file uses a Sigma/Falco-inspired YAML schema. The top-level `schema` field identifies the document type and version (e.g. `correlic-rules/v1`).

The YAML is designed to be human-readable first and machine-parseable second. Every rule, chain, and list entry is commented with the rationale for its inclusion — release as an audit artifact is the primary goal, not machine loading.

## Relationship to the Paper

§6 and §7 of the paper summarize the rule set in prose and qualitative tables. These files provide the concrete thresholds, path patterns, and confidence scores that the paper describes. Where the paper says *"Tier 1 credential files"*, this repository enumerates exactly which files are Tier 1. Where the paper references the `filepath.Match` audit finding (§8.3), `never_baseline.yaml` carries the explanatory comment about why the current three-list implementation replaced the original unsound version.

## Reproducibility

The attack scenarios in Appendix A of the paper can be executed against a deployment of the monitoring system described in §3; the expected detections correspond directly to the rule IDs in `rules.yaml` and the chain IDs in `chains.yaml`. See Appendix A of the paper for the exact bash reproduction commands.

## Auditing These Files

Every detection rule is individually bypassable — this is a property of rule-based detection in general, not a limitation specific to this system. Defense-in-depth comes from (a) kernel-level telemetry capture that is harder to evade than any single rule, and (b) chain correlation that requires multiple rules to be evaded simultaneously.

If you find a pattern that should be included and is not — particularly in `never_baseline.yaml` — please open an issue or pull request. Contributions are welcome.

## Citation

```bibtex
@techreport{mishra2026correlic,
  author      = {Ayush Mishra},
  title       = {Closing the {AI} Agent Trust Gap: Kernel-Level Runtime Security Monitoring for {AI} Agents},
  institution = {Correlic},
  year        = {2026},
  url         = {https://github.com/FuloxDev/correlic/blob/main/backend/docs/paper/correlic-paper.md},
  note        = {Technical report. Supplementary artifacts: \url{https://github.com/FuloxDev/correlic/tree/main/paper-supplementary}}
}
```

The repository root also carries a `CITATION.cff`, so GitHub's "Cite this repository" button produces the same reference. If the report is later deposited with a DOI or preprint server, the identifier will be added here.

## License

Released under **[Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/)**.

You are free to share, adapt, and use these artifacts for any purpose, commercial or non-commercial, as long as you give appropriate credit via the citation above.

## Related Links

- **Paper author:** [Ayush Mishra](https://orcid.org/0009-0002-3116-1969)
- **Project website:** [correlic.com](https://correlic.com)
- **Contact:** [LinkedIn](https://www.linkedin.com/in/ayush-mishra-9739a11a9/)
