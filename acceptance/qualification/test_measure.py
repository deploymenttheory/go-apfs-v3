"""Negative controls for the performance evidence admission and arithmetic."""

import gzip
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import measure


def job(identifier=1, **updates):
    value = dict(id=identifier, run_id=10, head_sha="revision", status="completed",
                 conclusion="success", labels=["macos-26"],
                 created_at="2026-10-01T00:00:00Z", started_at="2026-10-01T00:01:00Z",
                 completed_at="2026-10-01T00:03:00Z", steps=[])
    value.update(updates)
    return value


class MeasurementTests(unittest.TestCase):
    def test_wall_time_and_runner_consumption_are_distinct(self):
        jobs = [job(), job(2), job(3, conclusion="skipped")]
        result = measure.summarize(jobs)
        self.assertEqual(result["jobs_created"], 3)
        self.assertEqual(result["jobs_executed"], 2)
        self.assertEqual(result["macos_runner_minutes"], 4)
        self.assertEqual(result["macos_median_prestart_minutes"], 1)
        self.assertEqual(result["macos_peak_concurrency"], 2)

    def test_adjacent_intervals_do_not_overlap(self):
        later = job(2, started_at="2026-10-01T00:03:00Z", completed_at="2026-10-01T00:04:00Z")
        self.assertEqual(measure.peak_concurrency([job(), later]), 1)

    def test_duplicate_partial_failed_or_wrong_revision_evidence_is_rejected(self):
        for kind in ("valid", "duplicate", "partial", "failed", "wrong-revision", "wrong-run", "corrupt"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                j = job()
                jobs = [j, j] if kind == "duplicate" else [j]
                if kind == "failed":
                    j["conclusion"] = "failure"
                if kind == "wrong-revision":
                    j["head_sha"] = "other"
                if kind == "wrong-run":
                    j["run_id"] = 20
                original = json.dumps([dict(total_count=3 if kind == "partial" else len(jobs), jobs=jobs)]).encode()
                stored = gzip.compress(original, mtime=0)
                source = dict(path="jobs.gz", stored_sha256=hashlib.sha256(stored).hexdigest(),
                              original_sha256=hashlib.sha256(original).hexdigest(), run_id=10)
                (root / source["path"]).write_bytes(stored + (b"changed" if kind == "corrupt" else b""))
                if kind == "valid":
                    self.assertEqual(len(measure.load_jobs(root, source, "revision")), 1)
                else:
                    with self.assertRaises(ValueError):
                        measure.load_jobs(root, source, "revision")

    def test_original_baseline_metrics_reproduce(self):
        path = Path(__file__).resolve().parents[2] / "docs/qualification-evidence/baseline.json"
        ledger = json.loads(path.read_text())
        self.assertEqual(measure.measure(path), ledger["metrics"])


if __name__ == "__main__":
    unittest.main()
