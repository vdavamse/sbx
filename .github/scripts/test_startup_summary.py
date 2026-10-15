"""Tests for startup_summary.py: both hyperfine JSON shapes, and no crash on
an unknown shape. Run: python3 -m unittest .github/scripts/test_startup_summary.py"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import startup_summary as ss  # noqa: E402


def v1(times_bash, times_sbx):
    """hyperfine 1.x: per-run seconds in `times`."""
    return {"results": [
        {"command": "bash", "mean": 0.01, "times": times_bash},
        {"command": "sbx", "mean": 0.02, "times": times_sbx},
    ]}


def v2(times_bash, times_sbx):
    """hyperfine 2.x: per-run entries in `measurements`."""
    def entries(ts):
        return [{"time_wall_clock": {"value": t, "unit": "second"}, "exit_code": 0} for t in ts]
    return {"results": [
        {"command": "bash", "measurements": entries(times_bash), "summary": {}},
        {"command": "sbx", "measurements": entries(times_sbx), "summary": {}},
    ]}


class StartupSummaryTest(unittest.TestCase):
    def test_hyperfine_1_times_shape(self):
        lines, overhead, warning = ss.render(
            v1([0.010, 0.012, 0.011], [0.030, 0.032, 0.031]), ss.LABELS)
        self.assertAlmostEqual(overhead, 20.0, places=6)
        self.assertIsNone(warning)
        self.assertIn("| `/usr/bin/bash -c true` | 11.00 | 12.00 |", lines)

    def test_hyperfine_2_measurements_shape(self):
        lines, overhead, _ = ss.render(
            v2([0.010, 0.012, 0.011], [0.030, 0.032, 0.031]), ss.LABELS)
        self.assertAlmostEqual(overhead, 20.0, places=6)
        self.assertIn("| `sbx run --policy bench.json -- /usr/bin/bash -c true` | 31.00 | 32.00 |", lines)

    def test_warning_at_or_above_target(self):
        _, overhead, warning = ss.render(v1([0.010], [0.040]), ss.LABELS)
        self.assertAlmostEqual(overhead, 30.0, places=6)
        self.assertIn("30.0 ms", warning)

    def test_unknown_shape_is_na_and_never_raises(self):
        for doc in [
            {"results": [{"command": "x"}, {"command": "y"}]},
            {"results": [{"times": "not-a-list"}, {"measurements": [{"nope": 1}]}]},
            {"results": []},
            {},
            [],
            "junk",
        ]:
            lines, overhead, warning = ss.render(doc, ss.LABELS)
            self.assertIsNone(overhead)
            self.assertIsNone(warning)
            self.assertIn("Overhead: n/a", "\n".join(lines))

    def test_main_survives_unreadable_file(self):
        self.assertEqual(ss.main(["x", "/nonexistent/startup.json"]), 0)


if __name__ == "__main__":
    unittest.main()
