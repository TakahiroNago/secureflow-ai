#!/usr/bin/env python3
"""Line coverage of the backend from a Clover report, against docs/test-strategy.md §3.

Usage: python3 scripts/check-coverage.py backend/coverage.xml [--summary FILE]

Prints a Markdown table (also appended to --summary, for the CI job summary) and exits 1 when a target is missed.
Lines are counted from the <line type="stmt"> elements, which is what the "Total" of `pest --coverage` counts.
"""
import sys
import xml.etree.ElementTree as ET

TARGETS = [
    # (label, path prefix inside backend/, minimum percentage)
    ("app/Security", "app/Security/", 90.0),
    ("app/Domain", "app/Domain/", 90.0),
    ("backend (all)", "app/", 80.0),
]


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    report = sys.argv[1]
    summary = sys.argv[sys.argv.index("--summary") + 1] if "--summary" in sys.argv else None

    tree = ET.parse(report)
    totals = {label: [0, 0] for label, _, _ in TARGETS}

    for file_element in tree.iter("file"):
        name = file_element.get("name", "").replace("\\", "/")
        marker = "/app/"
        if marker not in name:
            continue
        relative = "app/" + name.split(marker, 1)[1]
        covered = executable = 0
        for line in file_element.iter("line"):
            if line.get("type") != "stmt":
                continue
            executable += 1
            if int(line.get("count", "0")) > 0:
                covered += 1
        for label, prefix, _ in TARGETS:
            if relative.startswith(prefix):
                totals[label][0] += covered
                totals[label][1] += executable

    rows = ["| Area | Line coverage | Target | Status |", "|---|---|---|---|"]
    failed = False
    for label, _, minimum in TARGETS:
        covered, executable = totals[label]
        pct = 100.0 * covered / executable if executable else 0.0
        ok = pct >= minimum
        failed = failed or not ok
        rows.append(f"| {label} | {pct:.1f}% ({covered} / {executable} lines) | >= {minimum:.0f}% | {'pass' if ok else '**FAIL**'} |")

    text = "## Backend line coverage\n\n" + "\n".join(rows) + "\n"
    print(text)
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(text + "\n")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
