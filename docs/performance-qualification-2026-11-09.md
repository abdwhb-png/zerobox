# ZeroBox filesystem performance qualification, 2026-11-09

The tested performance candidate did not meet the promotion gate. The daily runtime remains `native-42238285159-1`. Shared path storage was removed after its exploratory benefit failed to reproduce on the qualified artifacts. The retained Rust changes only reuse metadata already obtained within one operation and avoid evaluating an identical requested/resolved policy path twice; they carry no demonstrated latency improvement claim.

## Sources and qualification boundaries

| Role | Engine source | Native qualification |
| --- | --- | --- |
| Repaired reference | `93cb5b839d39aac0aa2e95f37ef60503463ee1f2` | [Reference qualification](https://github.com/abdwhb-png/my-pi-setup/actions/runs/42650614468) |
| Measured experimental candidate, including shared paths | `1ab34914ba557342408978e94b3b5c4965ce53c9` | [Experimental qualification](https://github.com/abdwhb-png/my-pi-setup/actions/runs/42653456872) |
| Retained implementation, without shared paths | `aefd404b7a4f4d69d2c12f26717f38661e5c51b8` | [Retained implementation qualification](https://github.com/abdwhb-png/my-pi-setup/actions/runs/42660849641) |

The performance numbers below describe the experimental candidate, not the pared-back implementation. The retained implementation needs a fresh performance campaign before any future performance-based promotion. Its [Linux CI](https://github.com/abdwhb-png/zerobox/actions/runs/42660156807) passed. The final native qualification is recorded separately and is not promotion authority by itself.

CI prerequisites were repaired before forming the reference: targeted compatible Cargo updates resolved the failing advisory checks, the protocol decoder was made compatible with current Clippy, Tokio's corrected descriptor-registration API replaced its deprecated constructor, and the existing HTTP/TLS fixture now supplies deterministic network test prerequisites. Bun's installation root is explicitly available to the development-tool fixture. Clippy's `--no-deps` matches the job's existing exclusion of upstream packages; compilation and Rust tests still cover those dependencies. The release workflow remains non-publishing and is manually dispatchable instead of using an invalid empty trigger.

## Measurement protocol and results

Measurements used the real Pi sandbox service, private runtime verification, admission supervision and cleanup through the versioned launcher in the Pi setup repository. The generic workload, matrix and comparator live in `scripts/performance/`. Preparation, native spawn to ready, and workload time are separate. Ready includes admission validation and the `child_started` event. No model or provider calls were involved.

The environment was WSL2, Node `/usr/bin/node` v24.18.0, the already-authorized Conda Python 3.13.5, Git `/usr/bin/git` 2.54.0 and Bun 1.4.3. The native reference and candidate used Rust 1.96.0 with the same static release command, lockfile and distribution inputs. Their Analysis components were identical; the shell component differed only in its declared engine helper. Workload, matrix, launcher and effective configuration hashes matched across the campaigns.

Each pair alternated runtime order and workload order. The index equally weights eight filesystem cases: metadata at depths 1, 3 and 8, descriptor metadata, reads by descriptor and path, open/close, and missing-path metadata. Each filesystem sample has 1,000 checked operations after warmup. Additional cases import 100 Node modules, import 100 Python modules and validate a synthetic Git index. Host controls use the same executable and fixture. A synthetic denied file is created after readiness and checked on every execution.

| Campaign | Paired batches | Estimated time reduction | Nominal 95% interval |
| --- | ---: | ---: | ---: |
| Local shared-path exploration versus metadata deduplication alone | 10 | 10.4% | 5.7% to 15.2% |
| Complete qualified candidate versus repaired reference | 10 | -5.4% | -14.2% to 1.8% |
| Fresh qualified confirmation campaign | 20 | 6.3% | -0.6% to 12.5% |

Positive values mean less time. Campaigns were analyzed separately without selecting or pooling samples. Intervals use the committed paired log-ratio percentile bootstrap with 10,000 resamples and seed zero. Across these campaigns, all 1,320 sample results, 120 startup measurements and 120 host/sandbox denial controls completed. No profiling or deliberate compilation ran during accepted timing campaigns.

The promotion rule required at least 10% estimated filesystem-index improvement, an interval excluding no gain, and no individual operation or startup interval confirming a regression above 5%. The twenty-pair result failed the first two conditions. No individual regression above 5% was established by that rule; this does not prove that every workload is unaffected. The broad intervals and the disagreement between campaigns prevent a reliable speed claim. The exploratory shared-path result must not be presented as a reproduced improvement.

## Functional validation

The local workspace library suite passed 730 tests with one pre-existing ignored test. The retained metadata changes then passed all 37 focused dynamic-filesystem tests after removing shared paths. The comparator passed seven checks, including incomplete/duplicate data, incorrect checksums and a single-operation regression despite an aggregate improvement. Pi lint passed with existing unrelated warnings; the local whole-agent typecheck was blocked by errors in the installed `pi-subagents` checkout outside these changes, while the pinned native qualification typecheck passed for the tested candidate. Distribution installation checks passed 13 tests.

The experimental native bundle was installed into a disposable home and exercised through real `bash` and `safe_bash` Pi sessions. Atomic rollback restored the previous runtime and passed the same fresh-session contract. The real daily entry was not switched. Local archive extraction required restricting newly created directory modes before validation; integrity and permission checks were not bypassed.

The Ownertek integration command was `pnpm --filter @ownertek/platform test:ui resources/js/components/__tests__/truncated-text.test.tsx`. One host control and one sandbox execution each passed exactly one file and seven tests. Each started with the same empty owned XDG cache; Corepack downloads were disabled and its installed cache was reused. Observed command times were 9.327 seconds on the host and 82.945 seconds in the sandbox. These are single functional checks, not an application performance estimate or a comparison against the daily runtime. Project files were unchanged and experimental caches were removed.

## Preserved evidence and deferred work

Raw manifests, samples, comparison JSON, exact source snapshots, artifact receipts and the deferred regression live under `~/.local/state/zerobox/performance/20261109-runtime-performance/`. The original investigation remains under `~/.local/state/zerobox/performance/20261109T143749Z/`. Setup probes rejected for provenance, private socket-path length, an unexposed system Python or incorrect cache metadata are excluded from accepted campaigns. No failed sample was changed into a successful one.

The descriptor-metadata defect was explicitly deferred. After external path replacement, an open file can report the replacement's metadata because this kernel issues FUSE `getattr` with `handle=None`. A handle-only implementation did not fix the mounted reproducer. The preserved patch adds two real mounted regressions, including a rename to a denied path. Solving object identity is a separate change; entry/attribute TTLs, live metadata and symlink resolution were not cached, and Git configuration and hardlink policy were not relaxed.

No runtime was promoted and no binary or package release was published. Work stayed in the existing ZeroBox `main` and Pi setup `develop` checkouts; no branch or worktree was created.
