"""Reproduce CI baseline metrics from original GitHub job API pages.

No network calls, native filesystem tools or test execution occur here. Step
timings cannot separate compilation inside go test from assertion time, and job
pre-start delay can include dependencies as well as waiting for a runner.
"""

import argparse
from collections import Counter
from datetime import datetime
import gzip
import hashlib
import json
from pathlib import Path
from statistics import median


def timestamp(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def elapsed(start, end):
    value = (timestamp(end) - timestamp(start)).total_seconds()
    if value < 0:
        raise ValueError("negative API duration")
    return value


def macos(job):
    return any(label.startswith(("macos-", "xcode-")) for label in job["labels"])


def step_category(name):
    if any(action in name for action in ("actions/download-artifact@", "actions/upload-artifact@")):
        return "transfer"
    if name.startswith(("Archive ", "Unpack ")):
        return "archive"
    if name.startswith("Build explicitly labelled"):
        return "explicit_build"
    if "setup-go@" in name or "checkout@" in name or name in ("Set up job", "Complete job"):
        return "setup_cleanup"
    return "checks_and_other"


def load_jobs(root, source, revision):
    stored = (root / source["path"]).read_bytes()
    if hashlib.sha256(stored).hexdigest() != source["stored_sha256"]:
        raise ValueError("stored job metadata digest mismatch")
    original = gzip.decompress(stored)
    if hashlib.sha256(original).hexdigest() != source["original_sha256"]:
        raise ValueError("original job metadata digest mismatch")
    pages = json.loads(original)
    jobs = [job for page in pages for job in page["jobs"]]
    if not pages or any(page["total_count"] != len(jobs) for page in pages):
        raise ValueError("incomplete job API pagination")
    if len({job["id"] for job in jobs}) != len(jobs):
        raise ValueError("duplicate job IDs")
    for job in jobs:
        if job["run_id"] != source["run_id"] or job["head_sha"] != revision:
            raise ValueError("job run/revision mismatch")
        if job["status"] != "completed" or job["conclusion"] not in ("success", "skipped"):
            raise ValueError("baseline campaign is incomplete or unsuccessful")
    return jobs


def peak_concurrency(jobs):
    events = []
    for job in jobs:
        if job["conclusion"] == "skipped":
            continue
        if timestamp(job["completed_at"]) > timestamp(job["started_at"]):
            events.extend(((timestamp(job["started_at"]), 1), (timestamp(job["completed_at"]), -1)))
    current = peak = 0
    # End before start at the same instant: intervals are half-open.
    for _, delta in sorted(events):
        current += delta
        peak = max(peak, current)
    return peak


def summarize(jobs):
    executed = [j for j in jobs if j["conclusion"] != "skipped"]
    mac_jobs = [j for j in executed if macos(j)]
    step_seconds = Counter()
    for job in executed:
        for step in job["steps"]:
            if step["status"] != "completed" or step["conclusion"] == "skipped":
                continue
            step_seconds[step_category(step["name"])] += elapsed(step["started_at"], step["completed_at"])
    def minutes(group):
        return round(sum(elapsed(j["started_at"], j["completed_at"]) for j in group) / 60, 3)
    def med_delay(group):
        return round(median(elapsed(j["created_at"], j["started_at"]) for j in group) / 60, 3) if group else 0
    return {
        "jobs_created": len(jobs),
        "jobs_executed": len(executed),
        "jobs_skipped": len(jobs) - len(executed),
        "runner_minutes": minutes(executed),
        "macos_jobs_executed": len(mac_jobs),
        "macos_runner_minutes": minutes(mac_jobs),
        "macos_peak_concurrency": peak_concurrency(mac_jobs),
        "macos_median_execution_minutes": round(median(elapsed(j["started_at"], j["completed_at"]) for j in mac_jobs) / 60, 3) if mac_jobs else 0,
        "macos_median_prestart_minutes": med_delay(mac_jobs),
        "macos_max_prestart_minutes": round(max((elapsed(j["created_at"], j["started_at"]) for j in mac_jobs), default=0) / 60, 3),
        "step_minutes_all_hosts": {k: round(v / 60, 3) for k, v in sorted(step_seconds.items())},
    }


def measure(path):
    ledger = json.loads(path.read_text())
    if ledger["schema"] != 1:
        raise ValueError("unsupported performance ledger schema")
    all_jobs = []
    campaigns = {}
    for source in ledger["sources"]:
        if source["name"] in campaigns:
            raise ValueError("duplicate campaign")
        jobs = load_jobs(path.parent, source, ledger["revision"])
        all_jobs.extend(jobs)
        campaigns[source["name"]] = summarize(jobs)
    if not campaigns or len({j["id"] for j in all_jobs}) != len(all_jobs):
        raise ValueError("missing campaigns or duplicate cross-campaign jobs")
    return {"campaigns": campaigns, "combined": summarize(all_jobs)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", type=Path, default=Path("docs/qualification-evidence/baseline.json"))
    parser.add_argument("--check", action="store_true", help="require exact agreement with recorded metrics")
    args = parser.parse_args()
    result = measure(args.ledger)
    if args.check and result != json.loads(args.ledger.read_text())["metrics"]:
        raise ValueError("recorded performance metrics differ from original API evidence")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
