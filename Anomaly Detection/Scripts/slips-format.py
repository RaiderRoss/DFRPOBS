#!/usr/bin/env python3
"""Render Slips alerts.log as colourised, aligned output.

Slips writes evidence lines like:

  2026-08-12T00:20:43.352512+00:00 (TW 1): Src IP 172.28.89.36        . \
Detected Connection to unknown destination port 24/TCP destination IP \
172.28.80.1. Threat level: medium.

which are hard to scan: the timestamp is longer than the useful part, the
source IP is padded with a runaway column of spaces, and the threat level —
the thing you actually want to triage on — is buried at the end of the line.

This reformats each line to put severity first (as colour and as a label),
then time, timewindow, source, and the description. Threat levels use Slips'
own scale: info, low, medium, high, critical.

Reads alerts.log on stdin. Use --no-color when piping to a file.
"""
import re
import sys
from collections import Counter

LINE = re.compile(
    r"^(?P<ts>\S+)\s+\(TW (?P<tw>\d+)\):\s+"
    r"Src IP (?P<src>\S+)\s+\.\s+"
    r"(?:Detected\s+)?(?P<desc>.*?)\s*"
    r"Threat level:\s*(?P<level>\w+)\.?\s*$"
)

# Ordered least to most severe, with an ANSI colour and a short glyph.
LEVELS = {
    "info":     ("\033[38;5;244m", "·"),   # grey  - context, not an accusation
    "low":      ("\033[38;5;72m",  "▪"),   # green
    "medium":   ("\033[38;5;179m", "▲"),   # amber
    "high":     ("\033[38;5;167m", "▲"),   # red
    "critical": ("\033[1;38;5;196m", "■"), # bright red, bold
}
ORDER = ["critical", "high", "medium", "low", "info"]
DIM, BOLD, RESET = "\033[38;5;244m", "\033[1m", "\033[0m"


def main() -> int:
    color = "--no-color" not in sys.argv
    # A live scan produces dozens of routine "connecting to a private IP"
    # entries at info level. Printed chronologically they bury the handful of
    # medium/high findings that matter, so --brief leads with severity and
    # collapses info to a count.
    brief = "--brief" in sys.argv
    # --stream prints each finding the moment it arrives, for `tail -f`.
    # The default path buffers all of stdin so it can sort and summarise,
    # which never terminates against a live log.
    stream = "--stream" in sys.argv

    def c(code: str) -> str:
        return code if color else ""

    def render(level: str, clock: str, tw: str, src: str, desc: str) -> str:
        col, glyph = LEVELS.get(level, (DIM, "·"))
        return (
            f"  {c(col)}{glyph} {level:<8}{c(RESET)}"
            f"{c(DIM)}{clock}  TW{tw}  {src:<15}{c(RESET)} {desc}"
        )

    def parse(raw: str):
        m = LINE.match(raw.strip())
        if not m:
            return None
        ts = m.group("ts")
        clock = ts.split("T")[1][:8] if "T" in ts else ts[:8]
        return (
            m.group("level").lower(),
            clock,
            m.group("tw"),
            m.group("src"),
            m.group("desc"),
        )

    if stream:
        for raw in sys.stdin:
            if not raw.strip():
                continue
            parsed = parse(raw)
            if parsed:
                print(render(*parsed), flush=True)
            else:
                print(f"    {c(DIM)}{raw.strip()}{c(RESET)}", flush=True)
        return 0

    counts: Counter = Counter()
    rows = []

    for raw in sys.stdin:
        raw = raw.rstrip("\n")
        if not raw.strip():
            continue
        m = LINE.match(raw.strip())
        if not m:
            rows.append((None, raw.strip()))
            continue

        level = m.group("level").lower()
        counts[level] += 1
        # 2026-08-12T00:20:43.352512+00:00 -> 00:20:43
        ts = m.group("ts")
        clock = ts.split("T")[1][:8] if "T" in ts else ts[:8]
        rows.append((level, (clock, m.group("tw"), m.group("src"), m.group("desc"))))

    if not rows:
        print(f"{c(DIM)}    (no evidence recorded yet){c(RESET)}")
        return 0

    def emit(level: str, row) -> None:
        col, glyph = LEVELS.get(level, (DIM, "·"))
        clock, tw, src, desc = row
        # Severity leads the line so the eye lands on it first.
        print(
            f"  {c(col)}{glyph} {level:<8}{c(RESET)}"
            f"{c(DIM)}{clock}  TW{tw}  {src:<15}{c(RESET)} {desc}"
        )

    if brief:
        rank = {lvl: i for i, lvl in enumerate(ORDER)}
        notable = [(l, r) for l, r in rows if l is not None and l != "info"]
        notable.sort(key=lambda x: (rank.get(x[0], 99), x[1][0]))
        for level, row in notable:
            emit(level, row)
        if not notable:
            print(f"  {c(DIM)}(nothing above info level yet){c(RESET)}")
        if counts["info"]:
            col, glyph = LEVELS["info"]
            print(
                f"  {c(col)}{glyph} {'info':<8}{c(RESET)}"
                f"{c(DIM)}{counts['info']} routine items "
                f"(connections to private IPs) — hidden{c(RESET)}"
            )
    else:
        for level, row in rows:
            if level is None:
                print(f"    {c(DIM)}{row}{c(RESET)}")
                continue
            emit(level, row)

    total = sum(counts.values())
    parts = []
    for lvl in ORDER:
        if counts[lvl]:
            col, _ = LEVELS[lvl]
            parts.append(f"{c(col)}{counts[lvl]} {lvl}{c(RESET)}")
    print()
    print(f"  {c(BOLD)}{total} evidence items{c(RESET)}  " + f"{c(DIM)}|{c(RESET)} ".join(parts))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        # Ctrl-C out of a live tail is the normal way to stop, not a crash.
        sys.exit(130)
    except BrokenPipeError:
        # Downstream closed (e.g. piped into head); exit quietly.
        sys.exit(0)
