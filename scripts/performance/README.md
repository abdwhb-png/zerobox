# Guarded filesystem performance

The workload and matrix are independent of Pi. They cover metadata at depths 1, 3 and 8, missing paths, open/close, reads by path and descriptor, 100 Node module imports, 100 Python imports and Git index validation. Preparation creates only synthetic files and a synthetic Git repository under a launcher-owned directory. It does not install dependencies. Node and Python import checksums must equal 4,950; every filesystem result is checked against the matrix.

The Pi launcher lives in `agent/extensions/sandbox/runtime/performance.ts` in the Pi setup repository. It uses the real sandbox service, private leases, runtime verification, admission supervision and cleanup. It accepts two complete runtime bundles without changing the managed daily executable. It loads the project's effective configuration, disables Corepack downloads in memory, and records configuration hashes without logging environment values. The project must already be trusted and its policy must deny `*.pem`; a synthetic file created after each command is ready checks that denial dynamically.

```sh
bun ~/.pi/agent/extensions/sandbox/runtime/performance.ts \
  --project /absolute/project --source-root /absolute/zerobox \
  --reference-bundle /absolute/reference --candidate-bundle /absolute/candidate \
  --output /absolute/new-output-directory --pairs 10 --iterations 1000
python3 scripts/performance/compare.py /absolute/new-output-directory/measurements.ndjson --pairs 10
```

The output directory must not exist. Use `--pairs 1 --iterations 10 --suite filesystem` for a smoke run, which is never sufficient for a promotion decision. `--node` and `--python` default to `/usr/bin/node` and `/usr/bin/python3`; the launcher records the actual Node executable and both versions. Optional `--reference-binary` or `--candidate-binary` overrides use the existing bundle's verified helper and components for local engine experiments. These runs record distinct engine and helper hashes and are explicitly unqualified. They cannot substitute for measuring the exact complete native CI artifact before promotion.

Each pair alternates execution order and task order. Commands use the same fixture, workload bytes, policy and inherited cache configuration. Filesystem samples use 1,000 operations after a ten-operation warmup; tool samples use one checked process after one warmup. Python bytecode writes are disabled so import trials do not mutate their fixtures. Separate almost-empty Node commands record Pi preparation, native spawn to ready, and total wall time. Ready means admission was validated and `child_started` was observed, not admission alone. Service setup is reported outside these startup samples.

Do not run profilers, compilers or other deliberately heavy work during accepted measurements. Keep profiling in separate runs. The filesystem index is the equal-weight geometric mean of the eight filesystem operation times, paired by run. The comparator reports individual medians and ranges, paired geometric ratios and deterministic 95% percentile bootstrap intervals with 10,000 resamples and seed zero. It rejects incomplete, duplicate, failed and checksum-invalid samples. A statistical pass requires at least 10% improvement in the filesystem index with an interval excluding no gain, and no operation or startup metric whose interval confirms a regression above 5%. Collect 20 new complete pairs if ten pairs remain inconclusive; do not select the fastest samples or mix runs. A statistical pass alone does not qualify a runtime: Rust CI, isolation contracts, native packaging and exact artifact identity remain separate requirements.

Application tests are additional integration evidence. Record their exact command, executable, source revision, output assertions and cache state. Restore the same owned experimental cache snapshot before each alternating trial when the application mutates caches. Do not clear or replace live user caches, download tools during samples, or use an application-specific result as the generic filesystem promotion gate.

Run comparator checks with `python3 -m unittest discover -s scripts/performance -p test_compare.py`. Existing baselines and deferred defects belong in the measurement report rather than silent exclusions or weakened assertions.

The [2026-11-09 qualification report](../../docs/performance-qualification-2026-11-09.md) records the rejected experimental candidate, retained changes and unchanged daily runtime.
