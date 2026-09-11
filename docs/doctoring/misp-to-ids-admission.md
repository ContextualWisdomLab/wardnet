# MISP `to_ids` admission policy

## Decision boundary

Wardnet converts selected MISP attributes into gateway enforcement material (`ThreatIndicator` and, for IPs, `DnsblEntry`). The conversion is therefore an admission decision, not a neutral JSON import. `to_ids` is treated as affirmative evidence that an attribute is intended for detection, and an attribute is admitted only when Wardnet can positively recognize that signal as true and can establish that the attribute has not been withdrawn.

The MISP object schema defines `to_ids` as a boolean, and the MISP-STIX converter documents that `to_ids=True` is the detection-ready case that becomes an Indicator. MISP REST search can also return attributes regardless of their `to_ids` setting unless the caller filters them. Wardnet consequently cannot infer IDS authorization from mere presence in a MISP document. Missing, `false`, `null`, object, array, and otherwise unrecognized `to_ids` values fail closed and contribute to `skipped_attributes`; they do not produce enforcement rows. The previously supported explicit scalar compatibility spellings (`"1"`, case-insensitive `"true"`, numeric `1`) remain accepted so the repair does not broaden unrelated parser incompatibility.

MISP's ZeroMQ contract exposes attribute deletion independently of `to_ids`: examples use `deleted: false`/`"0"` for active material and set `deleted` to `1` when an attribute is deleted, with subscribers instructed to inspect the deletion marker. MISP also gives an enclosing Object its own deletion lifecycle; the current event-object rendering path explicitly reads `object['deleted']` and marks the whole object deleted. A positive nested attribute `to_ids` value therefore cannot resurrect either a withdrawn attribute or a withdrawn parent Object. Wardnet treats recognized `deleted=true`/`1` states at either scope as withdrawn; recognized `false`/`0` states and an omitted `deleted` member remain active for compatibility with ordinary exports. A present but structurally unrecognized deletion state at either scope fails closed rather than becoming an implicit active signal.

This is the security-design application of fail-safe defaults: permission to create enforcement material is established by positive evidence rather than by the absence of a denial. Saltzer and Schroeder (1975) describe that protection principle as defaulting to lack of permission unless conditions for access are established. For the parser boundary here, the analogous safe state is “do not create an enforcement indicator” when the upstream authorization signal is absent, withdrawn, or structurally invalid.

The hostile regressions intentionally supply valid JSON whose admission members are semantically malformed, absent, or contradictory with lifecycle state. That test style is consistent with the fuzzing literature's treatment of syntactically and semantically malformed inputs as a primary way to expose security-relevant parser behavior (Manès et al., 2021). Wardnet already archives the permitted arXiv version of that survey at [`../papers/fuzzing-art-science-engineering-survey-arxiv-1812.00140.pdf`](../papers/fuzzing-art-science-engineering-survey-arxiv-1812.00140.pdf). The Saltzer–Schroeder paper is linked to the authors' MIT-hosted web rendering rather than copied into the repository because the hosted metadata retains the authors' 1975 copyright; this document does not manufacture a redistribution right.

## Alternatives considered

Keeping `unwrap_or(true)` for `to_ids` was rejected because an omitted field would silently become stronger evidence than MISP supplied. Treating arbitrary JSON values as true was rejected because a producer/schema defect would widen enforcement. Treating an unknown or malformed `deleted` value as active was rejected for the same reason: lifecycle ambiguity must not revive enforcement material. Ignoring an enclosing MISP Object's deletion marker was rejected because it allows a nested attribute to outlive the producer's parent-object withdrawal decision. Rejecting the entire MISP document was also rejected for this bounded repair: `skipped_attributes` already provides a per-attribute fail-closed path and allows valid sibling indicators to remain usable while preserving input-quality evidence. A future contract version may remove the legacy scalar compatibility spellings, but that is a separate compatibility decision and is not required to close this defect.

## Verification contract

`tests/misp_to_ids_admission.rs` is the focused security regression. It requires object, array, `null`, and missing `to_ids` values to be skipped while an explicit boolean `true` control remains admitted. It also requires attribute-level `deleted=true`, `deleted="1"`, and a structurally malformed deletion marker to be skipped even when `to_ids=true`, while `deleted=false`, `deleted="0"`, and omitted deletion state remain active. The parent-object hostile case requires nested otherwise-actionable attributes to be skipped when the enclosing MISP Object is deleted or has a structurally ambiguous deletion marker; recognized active and omitted parent deletion state remain compatible. Existing unit coverage retains boolean `to_ids=false` rejection and the supported explicit scalar compatibility cases. Merge evidence must come from the exact current PR head and then-live Wardnet CI/fuzz/security/review gates; source reasoning or predecessor runs are not a substitute.

## Traceability and references

MISP Project. (n.d.). *misp-objects: Definition, description and relationship types of MISP objects* (`schema_objects.json`). GitHub. https://github.com/MISP/misp-objects/blob/main/schema_objects.json

MISP Project. (n.d.). *MISP-STIX converter*. GitHub. https://github.com/MISP/misp-stix

MISP Project. (n.d.). *MISP ZeroMQ documentation*. GitHub. https://github.com/MISP/misp-book/blob/main/misp-zmq/README.md

MISP Project. (2026). *Event object row rendering* (`app/View/Elements/Events/View/row_object.ctp`, commit `9294667a5b40e59ea42314c2aafa99086ce1d8e6`). GitHub. https://github.com/MISP/MISP/blob/9294667a5b40e59ea42314c2aafa99086ce1d8e6/app/View/Elements/Events/View/row_object.ctp

Saltzer, J. H., & Schroeder, M. D. (1975). The protection of information in computer systems. *Proceedings of the IEEE, 63*(9), 1278–1308. https://doi.org/10.1109/PROC.1975.9939

Author-hosted rendering: https://web.mit.edu/saltzer/www/publications/protection/index.html

Manès, V. J. M., Han, H., Han, C., Cha, S. K., Egele, M., Schwartz, E. J., & Woo, M. (2021). The art, science, and engineering of fuzzing: A survey. *IEEE Transactions on Software Engineering, 47*(11), 2312–2331. https://doi.org/10.1109/TSE.2019.2946563

Repository archive: [`../papers/fuzzing-art-science-engineering-survey-arxiv-1812.00140.pdf`](../papers/fuzzing-art-science-engineering-survey-arxiv-1812.00140.pdf)
