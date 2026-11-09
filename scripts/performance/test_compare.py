import unittest

from compare import compare_runs


def samples(ratio=0.8):
    from compare import MATRIX
    rows = []
    for pair in range(10):
        for mode in ("reference", "candidate"):
            for task in MATRIX:
                rows.append({**task, "event": "measurement", "phase": "sample", "pair": pair,
                             "mode": mode, "n": 1, "checksum": task["checksumPerIteration"],
                             "elapsedMs": 100 if mode == "reference" else 100 * ratio})
            rows.append({"event": "startup", "pair": pair, "mode": mode,
                         "prepareMs": 50, "nativeToReadyMs": 2000})
    return rows


class ComparisonTests(unittest.TestCase):
    def test_confident_generic_gain_passes(self):
        report = compare_runs(samples())
        self.assertTrue(report["promotable"])
        self.assertAlmostEqual(report["filesystemIndex"]["ratio"], 0.8)

    def test_unchanged_runtime_does_not_pass(self):
        self.assertFalse(compare_runs(samples(1))["promotable"])

    def test_startup_regression_blocks_a_filesystem_gain(self):
        rows = samples()
        for row in rows:
            if row["event"] == "startup" and row["mode"] == "candidate":
                row["nativeToReadyMs"] *= 2
        self.assertFalse(compare_runs(rows)["promotable"])

    def test_one_operation_regression_blocks_the_aggregate_gain(self):
        rows = samples()
        for row in rows:
            if row["event"] == "measurement" and row["mode"] == "candidate" and row["op"] == "fstat":
                row["elapsedMs"] = 120
        report = compare_runs(rows)
        self.assertLess(report["filesystemIndex"]["ratio"], 0.9)
        self.assertFalse(report["promotable"])
        self.assertIn("fstat/8", report["confirmedRegressions"])

    def test_missing_measurement_is_an_error(self):
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            compare_runs(samples()[1:])

    def test_duplicate_measurement_is_an_error(self):
        rows = samples()
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            compare_runs(rows + [rows[0]])

    def test_failed_or_incorrect_workload_is_an_error(self):
        rows = samples()
        rows[0]["checksum"] = 0
        with self.assertRaisesRegex(ValueError, "checksum"):
            compare_runs(rows)


if __name__ == "__main__":
    unittest.main()
