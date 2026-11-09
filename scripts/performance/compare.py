#!/usr/bin/env python3
"""Evaluate paired, unprofiled runtime measurements; never activate a runtime."""
import argparse
import json
import math
from pathlib import Path
import random
import statistics

MATRIX = json.loads(Path(__file__).with_name("matrix.json").read_text())


def task_key(task):
    return task["op"] + "/" + str(task.get("depth", ""))


def estimate(reference, candidate):
    changes = [math.log(new / old) for old, new in zip(reference, candidate, strict=True)]
    rng = random.Random(0)
    bootstraps = sorted(math.exp(statistics.mean(rng.choices(changes, k=len(changes))))
                        for _ in range(10000))
    return {"ratio": math.exp(statistics.mean(changes)),
            "ci95": [bootstraps[249], bootstraps[9749]],
            "reference": {"median": statistics.median(reference), "min": min(reference), "max": max(reference)},
            "candidate": {"median": statistics.median(candidate), "min": min(candidate), "max": max(candidate)}}


def compare_runs(rows, pairs=10):
    if pairs not in (10, 20):
        raise ValueError("Promotion requires 10 or 20 complete pairs")
    measurements = {}
    tasks = {task_key(task): task for task in MATRIX}
    for row in rows:
        if row.get("event") == "failure":
            raise ValueError("Run contains a failed execution")
        if row.get("mode") not in ("reference", "candidate"):
            continue
        if row.get("event") == "startup":
            values = {"startup/prepare": row["prepareMs"], "startup/ready": row["nativeToReadyMs"]}
        elif row.get("event") == "measurement" and row.get("phase") == "sample":
            name = task_key(row)
            if name not in tasks:
                raise ValueError("Unknown sample: " + name)
            if row.get("error"):
                raise ValueError("Workload failed: " + name)
            if row["checksum"] != tasks[name]["checksumPerIteration"] * row["n"]:
                raise ValueError("Invalid workload checksum: " + name)
            values = {name: row["elapsedMs"] / row["n"]}
        else:
            continue
        for name, value in values.items():
            key = (row["mode"], row["pair"], name)
            if key in measurements:
                raise ValueError("Duplicate measurement: " + str(key))
            if not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
                raise ValueError("Invalid elapsed time: " + str(key))
            measurements[key] = value
    names = [*tasks, "startup/prepare", "startup/ready"]
    expected = {(mode, pair, name) for mode in ("reference", "candidate")
                for pair in range(pairs) for name in names}
    if set(measurements) != expected:
        raise ValueError("Incomplete or unexpected measurement pairs")
    metrics = {}
    for name in names:
        metrics[name] = estimate(*[[measurements[(mode, pair, name)] for pair in range(pairs)]
                                  for mode in ("reference", "candidate")])
    filesystem = [name for name, task in tasks.items() if task["family"] == "filesystem"]
    index = estimate(*[[math.exp(statistics.mean(math.log(measurements[(mode, pair, name)])
                                                for name in filesystem)) for pair in range(pairs)]
                       for mode in ("reference", "candidate")])
    regressions = [name for name, result in metrics.items() if result["ci95"][0] > 1.05]
    promotable = index["ratio"] <= 0.9 and index["ci95"][1] < 1 and not regressions
    uncertain = index["ci95"][0] <= 1 <= index["ci95"][1] or any(
        result["ratio"] > 1.05 and result["ci95"][0] <= 1.05 for result in metrics.values())
    return {"schemaVersion": 1, "pairs": pairs, "promotable": promotable,
            "needsMoreSamples": pairs == 10 and uncertain,
            "filesystemIndex": index, "confirmedRegressions": regressions, "metrics": metrics,
            "gate": {"minimumFilesystemGain": 0.1, "maximumConfirmedRegression": 0.05,
                     "confidence": 0.95, "bootstrapResamples": 10000, "seed": 0}}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("measurements", type=Path)
    parser.add_argument("--pairs", type=int, choices=(10, 20), default=10)
    args = parser.parse_args()
    report = compare_runs([json.loads(line) for line in args.measurements.read_text().splitlines()], args.pairs)
    print(json.dumps(report, indent=2))
