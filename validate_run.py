#!/usr/bin/env python3
"""
validate_run.py  <csv>  <intended_workload>  <duration_s>

Exit 0 if the CSV is a clean, complete run that analyse_synthetic.py will place
in <intended_workload>; non-zero (with a printed reason) otherwise.

It guards against the two failure modes seen in the System D re-run:

  1. Corruption   - binary/non-printable bytes or rows with the wrong field
                    count (the "UNREADABLE ... charmap" / "Expected 15 fields"
                    files), and truncated runs.
  2. Mislabelling - a run whose measured rate would make the analyser file it in
                    a NEIGHBOURING cell. On 16384 B the 2.65 and 2.69 Mbps
                    targets are only 0.04 apart, so this replicates the exact
                    classify() logic from analyse_synthetic.py and rejects any
                    run that does not land in the intended cell.

Kept deliberately dependency-free (stdlib only) so it runs on a stock Pi.
"""
import sys, csv

# --- mirror of analyse_synthetic.py, keep in sync -------------------------
RATE_TARGETS = {
    512:   {0.10: "telemetry_nbiot", 0.50: "telemetry_ltem"},
    16384: {0.62: "video_low_10fps", 1.85: "video_mean_30fps",
            2.65: "video_p95_30fps", 2.69: "video_stress_max"},
    32768: {1.85: "video_mean_2frame", 2.65: "video_p95_2frame",
            2.69: "video_stress_2frame"},
    65536: {1.85: "video_mean_4frame", 2.65: "video_p95_4frame",
            2.69: "video_stress_4frame"},
}
SAT_NAME = {512: "sat_512", 16384: "sat_16384",
            32768: "sat_32768", 65536: "sat_65536"}
RATE_PROBE_PACKETS = 31
EXPECT_FIELDS = 15


def classify(packet_bytes, rate):
    if packet_bytes not in RATE_TARGETS or rate is None:
        return None
    targets = RATE_TARGETS[packet_bytes]
    nearest = min(targets, key=lambda t: abs(rate - t))
    if abs(rate - nearest) <= 0.15 * nearest:
        return targets[nearest]
    if rate > max(targets) * 1.5:
        return SAT_NAME[packet_bytes]
    return None
# --------------------------------------------------------------------------

ALLOWED = bytes([9, 10, 13] + list(range(32, 127)))


def reject(msg):
    print("REJECT: " + msg)
    sys.exit(1)


def main():
    if len(sys.argv) != 4:
        sys.exit("usage: validate_run.py <csv> <intended_workload> <duration_s>")
    path, intended, dur = sys.argv[1], sys.argv[2], float(sys.argv[3])

    try:
        raw = open(path, "rb").read()
    except OSError as e:
        reject(f"cannot open ({e})")
    if not raw:
        reject("empty file")

    # 1a. binary corruption (the charmap-undecodable bytes)
    if raw.translate(None, ALLOWED):
        reject("non-printable byte(s) present (binary corruption)")

    lines = raw.decode("ascii").splitlines()
    if len(lines) < 2:
        reject("no data rows")

    # 1b. every non-empty line must have exactly 15 fields (torn/merged rows)
    for i, ln in enumerate(lines):
        if ln and ln.count(",") != EXPECT_FIELDS - 1:
            reject(f"line {i + 1} has {ln.count(',') + 1} fields, expected {EXPECT_FIELDS}")

    # parse valid data rows (skip the -1 warmup marker), keep first-31 for rate
    ts_all, b, probe = [], None, []
    for row in csv.reader(lines[1:]):
        if len(row) < 3 or row[1] == "-1":
            continue
        try:
            t, bb = int(row[0]), int(row[2])
        except ValueError:
            continue
        b = bb
        ts_all.append(t)
        if len(probe) < RATE_PROBE_PACKETS:
            probe.append(t)
    if b is None or len(ts_all) < 2:
        reject("fewer than 2 valid packets")

    # 1c. truncation: the run must span ~the full requested duration
    span = ts_all[-1] - ts_all[0]
    if span < 0.85 * dur * 1e9:
        reject(f"run spans only {span / 1e9:.1f}s of {dur:.0f}s (truncated)")

    # 2. must classify into the intended cell
    rate = None
    if len(probe) >= 2 and probe[-1] > probe[0]:
        rate = (len(probe) - 1) * b * 8 / ((probe[-1] - probe[0]) / 1e9) / 1e6
    got = classify(b, rate)
    if got != intended:
        rs = f"{rate:.3f}" if rate is not None else "NA"
        reject(f"classifies as {got} (bytes={b}, rate={rs} Mbps), not {intended}")

    print(f"OK: {intended}  bytes={b}  rate={rate:.3f} Mbps  "
          f"{len(ts_all)} packets  {span / 1e9:.1f}s")
    sys.exit(0)


if __name__ == "__main__":
    main()
