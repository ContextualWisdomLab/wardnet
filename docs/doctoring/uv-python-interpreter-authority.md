# uv Python interpreter authority: causal admission evidence

## Decision record

Wardnet treats an explicit `uv pip install --python <INTERPRETER>` or `-p <INTERPRETER>` selection as caller-controlled installation-environment authority. The existing admission policy therefore blocks the request with `alternate_install_root`. This document does not make Wardnet responsible for Python discovery, environment activation, package execution, isolation, or egress; those remain outside Agent Artifact Admission and with their canonical owners.

The current defect was narrower than an admission bypass. On the exact parent candidate `142c473b0d706f2a75533f683b1ceae429b442e2`, the assigned form `--python=/usr/bin/python3` was already blocked causally with `alternate_install_root`. The separate form `--python /usr/bin/python3` was also blocked, but `/usr/bin/python3` was additionally counted as a package operand, adding a false `artifact_not_approved` reason. Security evidence must distinguish the authority that actually caused denial from unrelated artifact-policy failures.

The minimum repair keeps the existing install-root classifier unchanged and changes only artifact-operand extraction: the value consumed by the already-recognized `uv` `--python`/`-p` selector is option data rather than a package operand. A genuine second package operand remains `artifact_not_approved`.

## RED → GREEN evidence

- Parent: `feat/agent-artifact-admission@142c473b0d706f2a75533f683b1ceae429b442e2`.
- Formatted RED head: `c0bddd842c07b91943904bf0334f1c9bd63960e5`.
- Hosted CI `34590170121` reached semantic Test RED after formatting passed. The approved baseline and assigned form passed; the separate long form returned `[AlternateInstallRoot, ArtifactNotApproved]` instead of the single causal `AlternateInstallRoot` reason.
- Repair contract: assigned long form, separate long form, and separate short `-p` form all remain fail-closed with `AlternateInstallRoot`; an additional undeclared package operand combined with a Python selector must still add `ArtifactNotApproved`.
- Final GREEN is accepted only from the unchanged current repair head after its repository workflows finish successfully; predecessor receipts are historical evidence only.

## Security rationale and owner boundary

Astral documents `--python, -p` for `uv pip install` as selecting the Python interpreter into which packages are installed and cautions that an alternative interpreter path can modify a system Python installation. That makes interpreter selection material to the destination/effective environment of an admitted install, not package identity. Wardnet may classify that submitted authority and emit durable admission evidence, but it does not discover the effective runtime environment or execute the install.

Peer-reviewed software-supply-chain research supports treating dependency-manager installation as a security-sensitive boundary and retaining evidence that identifies the exact operation and artifact authority being exercised. Ohm et al. (2020) analyzed 174 malicious packages distributed through npm, PyPI, and RubyGems and explicitly linked dependency-manager resolution and installation to real supply-chain attack paths. Torres-Arias et al. (2019) showed that end-to-end supply-chain integrity depends on verifiable evidence for the steps and artifacts that actually participated in delivery. Neither paper specifies `uv` command-line syntax; together they support the narrower Wardnet decision that package-manager admission and its audit reasons must remain precise rather than conflating an interpreter selector with a package operand.

This control follows the secure-development principle of repairing the root parsing/evidence defect rather than weakening the denial or treating the false secondary reason as harmless. NIST's current SSDF 1.2 work continues to emphasize secure and reliable development practices that address vulnerability root causes; the cited revision is an Initial Public Draft and is therefore supporting guidance rather than a finalized requirement. OWASP's 2026 agent-security work likewise emphasizes constraining the effective reach of agent tools and permissions. Those sources support a narrow deterministic admission boundary; they do not transfer quarantine, runtime, identity, egress, or orchestration ownership into Wardnet.

The academic papers are cited and linked rather than vendored in this PR; Wardnet does not infer repository redistribution rights from public availability alone.

## Traceability

| Evidence / requirement | Wardnet control |
| --- | --- |
| `uv pip install --python/-p` selects the installation interpreter/environment | `requests_alternate_install_root` keeps `--python` and `-p` fail-closed as `AlternateInstallRoot` |
| Option values are not package operands | `validate_artifact_operands` excludes only the value consumed by separate `--python`/`-p` |
| Real undeclared package operands remain denied | hostile regression combines `--python` with an extra package and requires `ArtifactNotApproved` |
| Durable evidence identifies the causal authority | selector-only cases require exactly `AlternateInstallRoot` |
| Foreign execution/isolation/egress authority is not duplicated | no installer execution, environment discovery, sandbox, egress, or orchestration implementation is added |

## References

Astral Software. (2026). *uv command reference: uv pip install*. https://docs.astral.sh/uv/reference/cli/

National Institute of Standards and Technology. (2025). *Secure Software Development Framework (SSDF) version 1.2: Recommendations for mitigating the risk of software vulnerabilities* (NIST SP 800-218r1, Initial Public Draft). https://csrc.nist.gov/news/2025/draft-ssdf-version-1-2

Ohm, M., Plate, H., Sykosch, A., & Meier, M. (2020). Backstabber's knife collection: A review of open source software supply chain attacks. In *Detection of intrusions and malware, and vulnerability assessment (DIMVA 2020)* (Lecture Notes in Computer Science, Vol. 12223, pp. 23–43). Springer. https://doi.org/10.1007/978-3-030-52683-2_2

OWASP GenAI Security Project. (2026, September 1). *OWASP GenAI Security Project unveils 2026 Top 10 for LLM applications, new Agent Control Standard and sponsors as community tops 30,000 members*. https://genai.owasp.org/2026/09/01/owasp-genai-security-project-unveils-2026-top-10-for-llm-applications-new-agent-control-standard-and-sponsors-as-community-tops-30000-members/

Torres-Arias, S., Afzali, H., Kuppusamy, T. K., Curtmola, R., & Cappos, J. (2019). in-toto: Providing farm-to-table guarantees for bits and bytes. In *28th USENIX Security Symposium (USENIX Security 19)* (pp. 1393–1410). USENIX Association. https://www.usenix.org/conference/usenixsecurity19/presentation/torres-arias
