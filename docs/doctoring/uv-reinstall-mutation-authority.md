# uv reinstall mutation authority

Verified 2026-09-11 against the current uv command reference, NIST SP 800-53 Release 5.2.0, and CWE 4.20. This note records the narrow evidence behind Wardnet's Agent Artifact Admission rule for `uv pip install` mutation semantics. It does not make Wardnet an installer, package resolver, filesystem authority, or quarantine runtime.

## Problem

A reviewed Python artifact coordinate authorizes the submitted package identity and the reviewed installation capability. It does not, by itself, authorize the caller to force replacement of packages that the executor would otherwise leave installed.

The uv command reference documents `--reinstall` and its alias `--force-reinstall` as reinstalling packages regardless of whether they are already installed. It separately documents `--reinstall-package <REINSTALL_PACKAGE>` as reinstalling a selected package regardless of installed state. Those switches change mutation semantics without changing the reviewed package coordinate. If admission treats them as ordinary argv, a caller can acquire replacement authority that was absent from the reviewed intent.

This is an admission-control problem, not installed-state inspection. Wardnet only classifies the submitted command before execution. The canonical execution/isolation owner remains responsible for the actual environment, filesystem, cleanup, and recovery semantics.

## Decision

For the current `uv pip install` admission profile:

- caller-supplied `--reinstall` fails closed as `artifact_not_approved`;
- caller-supplied `--force-reinstall` fails closed as the same unreviewed mutation authority;
- caller-supplied `--reinstall-package` and `--reinstall-package=<value>` fail closed as the same authority;
- exact command grammar is limited to the documented `uv pip install` path; unrelated uv commands do not inherit this classifier;
- direct `pip` and `pip3` retain their existing mutation-option behavior;
- Wardnet does not inspect installed packages, decide what should be replaced, execute uv, or infer ambient uv configuration.

A future approved reinstall capability would require a separately versioned policy contract that binds the mutation scope explicitly. It must not be inferred from ordinary artifact approval.

## RED → repair evidence

Hosted RED head `e2ef6f13eb2c19672967c20a73fa6bcb9f8e1dfa`, CI run `34553625991`, reached the actual admission assertions after formatting succeeded. The reviewed ordinary uv install remained `Allow`, while `--reinstall`, `--force-reinstall`, and `--reinstall-package=cwl-example` were all incorrectly `Allow` rather than `Block`. Existing direct-pip force-reinstall and ignore-installed contracts passed in the same workspace run, isolating the defect to uv classification.

Production repair `0d8e61d584965f9835f68e79b722eb5be7f0fbb2` extends the existing PyPI mutation-authority classifier to exact `uv pip install` grammar and recognizes the documented reinstall selectors. A domain-local unit contract also binds both the separate-value option token and attached-value spelling without depending on positional-artifact rejection. Exact-head GREEN is required after this doctoring commit; predecessor check conclusions do not transfer.

## Standards traceability

NIST SP 800-53 Release 5.2.0 is the current published control release. The relevant control-family relationship is configuration management: CM-3 requires controlled configuration changes and CM-5 restricts access to configuration changes. Wardnet's fail-closed classification is an implementation-level supporting control: unreviewed argv cannot silently add replacement semantics to an approved package action. This mapping is evidence traceability, not a claim that one admission rule alone satisfies either control.

CWE-15, *External Control of System or Configuration Setting*, describes the weakness class in which externally supplied input controls settings or values that affect system behavior. The uv reinstall selectors are caller-controlled command settings that alter mutation behavior, so CWE-15 is a suitable root-cause mapping. The mitigation applied here is privilege separation at the admission boundary: ordinary artifact approval is not treated as mutation authority.

## APA 7 references

Astral Software Inc. (2026). *Commands | uv*. Retrieved September 11, 2026, from https://docs.astral.sh/uv/reference/cli/

MITRE. (2026). *CWE-15: External control of system or configuration setting (Version 4.20)*. https://cwe.mitre.org/data/definitions/15.html

National Institute of Standards and Technology. (2020). *Security and privacy controls for information systems and organizations (NIST Special Publication 800-53, Revision 5; Release 5.2.0 issued August 27, 2025)*. U.S. Department of Commerce. https://doi.org/10.6028/NIST.SP.800-53r5
