# npm-family dependency-closure admission trace

Verified 2026-09-05. This note records the evidence for Wardnet's v0.1 decision to reject direct npm-family resolver installs until the admission contract can bind the material set they may install. It does not assign dependency resolution to Wardnet; dependency resolution remains external to the Agent Artifact Admission bounded context.

## Decision

`npm install <pkg>`, `pnpm add/install <pkg>`, `yarn add <pkg>`, and `bun add/install <pkg>` can turn one reviewed direct package operand into a transitive dependency closure. The current `InstallIntent` and `AdmissionPolicy` bind direct artifact coordinates and digests but do not carry a reviewed lockfile/material-set identity that proves the transitive closure. Wardnet therefore fails these direct resolver paths closed as `artifact_not_approved` even when the direct coordinate and execution-hardening flags match policy.

This is a dependency-authority decision, not a claim that the package managers are unsafe. `--ignore-scripts` and pnpm's `--ignore-pnpmfile` constrain execution hooks; they do not prove which transitive artifacts the resolver will select. A package manager's lockfile or frozen mode is also not self-authorizing: the admission contract must first bind the reviewed lockfile/material set and the execution broker must preserve and verify that identity through retrieval and installation.

## Primary-source observations

| Package manager | Current primary-source behavior | Consequence for a future Wardnet allow path |
| --- | --- | --- |
| npm | `npm ci` requires an existing `package-lock.json`/`npm-shrinkwrap.json`, exits when the lock does not match `package.json`, installs the whole project, and does not write the manifest or lockfile. npm describes these installs as essentially frozen. | Prefer a reviewed project/lockfile contract over direct `npm install <pkg>`; bind any tree-shaping project configuration used to create the lock. |
| pnpm | `pnpm install --frozen-lockfile` does not generate a lockfile and fails when the lockfile is absent, out of sync with the manifest, or would need an update. | A future port can require a reviewed `pnpm-lock.yaml` digest/material set plus frozen project install, while retaining workspace/configuration authority controls. |
| Yarn | `yarn install --immutable` aborts when the install would modify the lockfile; `--immutable-cache` and `--check-cache` add cache mutation/checksum controls. | A future port can bind the reviewed lockfile/material set and explicitly choose any additional cache-integrity requirements rather than authorizing `yarn add`. |
| Bun | `bun install --frozen-lockfile` installs exact versions from `bun.lock` and fails when the manifest disagrees; `bun ci` is documented as equivalent. | A future port can bind `bun.lock`/material identity and frozen project installation while separately constraining Bun configuration, platform selection, and trusted lifecycle authority. |

## Wardnet boundary and acceptance criteria

The current fail-closed repair is complete only when hostile tests prove that all supported direct npm-family resolver commands block after every existing direct-coordinate and safety check would otherwise pass. Positive admission coverage remains on package-manager paths whose current grammar can be bounded by the reviewed intent, such as exact Cargo installs and PyPI installs with `--require-hashes --no-deps`; this prevents the repair from degenerating into a global deny-all evaluator.

A future npm-family allow capability requires a new versioned contract with, at minimum:

- immutable reviewed project-manifest and lockfile digests;
- an explicit material/dependency-set identity derived from the reviewed lockfile rather than from runtime resolver output;
- package-manager/version semantics sufficient to interpret that lockfile without mutable or ambient trust/configuration authority;
- a frozen project-install command shape that fails rather than rewriting the lockfile;
- broker verification that retrieved bytes/provenance correspond to the admitted material set before execution;
- replay/idempotency and audit evidence binding the request, policy revision, lock/material identity and execution receipt;
- hostile tests for lock/manifest mismatch, lock mutation, workspace expansion, alternate registry/config, platform/optional/peer variant drift, cache poisoning, post-admission substitution and dependency-set mismatch.

This future work stays within Wardnet's admission/evidence responsibility only for policy evaluation and receipts. The execution broker preserves the admitted identity, `quarantine-sandbox-runtime` owns hostile execution isolation, and registry/provenance providers remain behind versioned ports/ACLs.

## APA 7 references

Bun. (2026). *bun install.* https://bun.com/docs/pm/cli/install

npm, Inc. (2026). *npm ci.* https://docs.npmjs.com/cli/v11/commands/npm-ci/

pnpm contributors. (2026). *pnpm install.* https://pnpm.io/cli/install

Yarn contributors. (2026). *yarn install.* https://yarnpkg.com/cli/install
