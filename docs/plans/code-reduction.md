# Reduce sud0's product and implementation surface

## Objective

Reduce the repository from 7,130 `tokei` code lines to no more than 5,704 while retaining the privileged execution architecture.
Aim for no more than 5,550 lines before final adversarial review so necessary restorations do not miss the hard gate.
Treat the work as an intentional 0.x product contraction rather than preserving incidental compatibility.

## Retained product

Keep command execution, `--chdir`, repeatable `--setenv NAME[=VALUE]`, descriptions, explicit and automatic PTY/pipe selection, non-interactive authorization, the fallback terminal PolicyKit agent, descriptor-backed cwd execution, and command exit-status propagation.

Require all CLI text and imported environment values to be UTF-8.

## Removed product and representations

Remove validation-only mode and its D-Bus method.
Remove client-claimed cwd text from the execution request.
Remove request and presentation digests.
Remove shell-runnable command rendering and forensic prompt placeholders.
Remove the handwritten request codec and prompt-template parser in favor of Postcard and Leon.
Remove the handwritten man page and private D-Bus reference documents; Clap owns CLI help and zbus owns runtime introspection.
Remove tests that exercise dependencies, tautologies, or test-only models rather than retained sud0 behavior.

## Preserved security invariants

The broker MUST derive caller identity from authenticated D-Bus credentials and retain the pidfd-based parent binding and UID checks.
Invocation methods MUST remain restricted to their creating unique bus name.
Owner loss, explicit cancellation, and broker shutdown MUST retain their cancellation behavior.
The broker MUST validate the complete owned request before authorization.
Cancellation MUST retain precedence over racing authorization success.
The broker MUST recheck ownership after authorization and MUST NOT create the sealed request or launch a unit before successful authorization.
The cwd MUST remain an opened, validated directory descriptor and execution MUST use that descriptor through `fchdir`.
The executor MUST independently validate activation metadata, descriptor shape, request seals, encoded bounds, request semantics, root UID state, terminal shape, and inherited descriptor closure.
The target environment MUST remain explicitly constructed, protected names MUST remain rejected, bare commands MUST use the fixed absolute search path, and execution MUST never fall back to a shell.
Systemd transient-unit isolation, startup/completion tracking, cancellation, stop-on-error, and reference cleanup MUST remain.
PTY byte forwarding, resize, output draining, suspend/resume, and terminal restoration MUST remain.
Invocation quotas and terminal-object expiry MUST remain.

## Implementation

1. Convert command, argument, cwd, environment option, imported environment, and frozen request values to UTF-8 strings while retaining all structural and resource validation.
2. Store `IoMode` directly and remove the redundant request-options wrapper and client cwd payload.
3. Replace the custom protocol with a versioned private Postcard DTO, applying the encoded-size cap before decode, rejecting trailing bytes, and reconstructing only through validated `FrozenRequest` state at both broker and executor boundaries.
4. Retain the sealed memfd boundary but remove its redundant creator-side reread.
5. Replace prompt parsing and rendering with Leon, allowing only command, cwd, description-line, and environment-count-line placeholders.
6. Replace shell syntax with a bounded, visibly separated argv display that escapes controls, structural delimiters, bidi controls, and markup-sensitive characters.
7. Reject requests whose complete sanitized presentation exceeds a display bound instead of truncating hidden content or displaying hashes.
8. Remove cwd identity collection, request/description digests, full environment disclosure, and their supporting dependencies and tests.
9. Remove validation mode through CLI, client, authorization, broker, and D-Bus declarations.
10. Simplify invocation status, completion, authentication-agent cleanup, prepared launch values, terminal helpers, descriptor wrappers, constants, exports, and errors without weakening retained lifecycle behavior.
11. Delete the man page and private D-Bus reference files and remove their distribution plumbing.
12. Remove obsolete dependencies and features, then audit every remaining direct dependency and enabled feature against a source use.
13. Delete disconnected and dependency-only tests, and consolidate retained boundary evidence into compact labeled tables and shared fixtures.
14. Review the full cumulative change through security, behavior, test-evidence, dependency, and deletion lenses; apply defensible cuts and restorations until repeated fresh deletion reviews converge.

## Reduction accounting

Measure the same repository-root `tokei` Code column after every implementation commit.
Record total and Rust code plus production, test, and documentation/asset deltas.
Code movement and formatting do not count as reduction.

## Completion policy

Every implementation item MUST be complete or superseded by a smaller equivalent.
The final repository MUST contain no more than 5,704 code lines after review-driven restorations.
No unresolved correctness or security finding may remain.
Two consecutive fresh deletion reviews MUST produce no accepted cut.

If retained behavior or security requirements prevent reaching the numeric gate, keep this plan, report the exact deficit and rejected cuts, and request an explicit further product reduction.
Delete this plan in a standalone `unplan:` commit only after all completion conditions are met.
