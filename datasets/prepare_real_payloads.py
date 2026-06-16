#!/usr/bin/env python3
"""prepare_real_payloads.py

Pre-process the four source datasets into five flat binary files of fixed-size
records for Experiment 6 (real-dataset payload validation).  Each record is one
packet's plaintext: exactly RECORD_SIZE bytes, zero-padded, and truncated only
where a source line exceeds the slot.  The harness (harness/dataset_source.hpp)
reads these files sequentially at run time and wraps to the start on EOF.

Run once on the development machine, then copy the resulting .bin files to each
Pi's LOCAL storage (e.g. ~/datasets/real_payloads/).  Do not generate them on
the Pi: the single-frame video file is on the order of tens of GB.

Outputs (written to --out-dir):
  real_payloads_telemetry_nbiot.bin   512 B    TON_IoT *.log + UCI power rows
  real_payloads_telemetry_ltem.bin    512 B    Edge-IIoTset normal-traffic CSV rows
  real_payloads_video_1frame.bin      16384 B  UCF-Crime PNG frames
  real_payloads_video_2frame.bin      32768 B  UCF-Crime frame pairs
  real_payloads_video_4frame.bin      65536 B  UCF-Crime frame quads

Usage:
  python3 prepare_real_payloads.py --datasets-root /path/to/datasets
  python3 prepare_real_payloads.py --datasets-root . --max-records 1000   # quick test
"""

import argparse
import sys
from pathlib import Path

# Record sizes (bytes) — must match the workload packet sizes in the run scripts.
NBIOT_SZ = 512
LTEM_SZ  = 512
F1_SZ    = 16384
F2_SZ    = 32768
F4_SZ    = 65536


def pad_or_trunc(data: bytes, size: int) -> bytes:
    """Zero-pad data up to size, or truncate if it is longer."""
    if len(data) >= size:
        return data[:size]
    return data + b"\x00" * (size - len(data))


def write_records(out_path: Path, records, record_size: int,
                  max_records=None, max_mb=None) -> int:
    """Write an iterable of byte records as fixed-size slots; verify the size.

    The record cap is the smaller of --max-records (if given) and the number of
    records that fit in --max-mb megabytes.  This keeps each file to a sensible
    size: the full UCF-Crime corpus would otherwise make each video file ~22 GB.
    The harness reads the file cyclically, so a few hundred MB of real bytes is
    ample, and throughput/latency are content-independent in any case."""
    cap = None
    if max_mb is not None:
        cap = max(1, int(max_mb * 1_000_000 // record_size))
    if max_records is not None:
        cap = max_records if cap is None else min(cap, max_records)

    n = 0
    with open(out_path, "wb") as f:
        for rec in records:
            f.write(pad_or_trunc(rec, record_size))
            n += 1
            if cap and n >= cap:
                break
    size = out_path.stat().st_size
    assert size == n * record_size, (
        f"{out_path.name}: file size {size} is not {n} x {record_size}"
    )
    print(f"  {out_path.name:38s} {n:>10,} records  {size / 1e6:>10.2f} MB")
    return n


# --- record generators ---------------------------------------------------

def iter_lines(paths, skip_header=False):
    """Yield each non-empty line (without the newline) as raw bytes."""
    for p in paths:
        try:
            with open(p, "rb") as f:
                if skip_header:
                    next(f, None)
                for line in f:
                    line = line.rstrip(b"\r\n")
                    if line:
                        yield line
        except OSError as e:
            print(f"  WARN: cannot read {p}: {e}", file=sys.stderr)


def iter_png(paths):
    """Yield the raw bytes of each PNG file."""
    for p in paths:
        try:
            yield p.read_bytes()
        except OSError as e:
            print(f"  WARN: cannot read {p}: {e}", file=sys.stderr)


def iter_concat(paths, n):
    """Yield concatenations of n consecutive PNG byte arrays; drop any final
    partial group of fewer than n frames."""
    group = []
    for p in paths:
        try:
            group.append(p.read_bytes())
        except OSError as e:
            print(f"  WARN: cannot read {p}: {e}", file=sys.stderr)
            continue
        if len(group) == n:
            yield b"".join(group)
            group = []


def interleave(*iterables):
    """Round-robin records from several iterables (for mixed NB-IoT traffic)."""
    iters = [iter(it) for it in iterables]
    while iters:
        for it in list(iters):
            try:
                yield next(it)
            except StopIteration:
                iters.remove(it)


# --- source discovery ----------------------------------------------------

def discover(root: Path):
    """Locate the source files under root by convention, tolerant of the exact
    directory layout.  Returns a dict of file lists; empties are reported."""
    low = lambda p: str(p).lower()
    ton_logs = sorted(p for p in root.rglob("*.log") if "ton" in low(p))
    uci_files = sorted(root.rglob("household_power_consumption.txt"))
    edge_csv = sorted(p for p in root.rglob("*.csv") if "normal traffic" in low(p))
    ucf_png = sorted(p for p in root.rglob("*.png")
                     if ("ucf" in low(p) or "crime" in low(p)))
    return {
        "ton_logs": ton_logs,
        "uci": uci_files,
        "edge_csv": edge_csv,
        "ucf_png": ucf_png,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--datasets-root", default=".",
                    help="Root directory containing the four source datasets.")
    ap.add_argument("--out-dir", default=None,
                    help="Output directory (default: <datasets-root>/real_payloads).")
    ap.add_argument("--max-records", type=int, default=None,
                    help="Hard cap on records per file (for a quick end-to-end test).")
    ap.add_argument("--max-mb", type=float, default=256.0,
                    help="Cap each output file to about this many MB (default 256). "
                         "Pass 0 for no size cap, i.e. the full corpus, which makes "
                         "each video file roughly 22 GB.")
    args = ap.parse_args()

    # --max-mb 0 means "no size cap".
    max_mb = None if args.max_mb == 0 else args.max_mb

    root = Path(args.datasets_root).expanduser().resolve()
    out = Path(args.out_dir).expanduser().resolve() if args.out_dir else root / "real_payloads"
    out.mkdir(parents=True, exist_ok=True)

    print(f"Datasets root : {root}")
    print(f"Output dir    : {out}")
    src = discover(root)
    for k, v in src.items():
        print(f"  found {k:10s}: {len(v)} file(s)")
    print("Writing payload files:")

    made = 0

    # 1. NB-IoT telemetry: TON_IoT JSON-line logs interleaved with UCI power rows.
    if src["ton_logs"] or src["uci"]:
        recs = interleave(
            iter_lines(src["ton_logs"]),
            iter_lines(src["uci"], skip_header=True),  # UCI file has a header line
        )
        made += 1
        write_records(out / "real_payloads_telemetry_nbiot.bin", recs, NBIOT_SZ, args.max_records, max_mb)
    else:
        print("  SKIP real_payloads_telemetry_nbiot.bin (no TON_IoT or UCI source found)")

    # 2. LTE-M telemetry: Edge-IIoTset normal-traffic CSV rows (header skipped).
    if src["edge_csv"]:
        recs = iter_lines(src["edge_csv"], skip_header=True)
        made += 1
        write_records(out / "real_payloads_telemetry_ltem.bin", recs, LTEM_SZ, args.max_records, max_mb)
    else:
        print("  SKIP real_payloads_telemetry_ltem.bin (no Edge-IIoTset normal CSVs found)")

    # 3-5. Video: UCF-Crime PNG frames, single / 2-frame / 4-frame bundles.
    if src["ucf_png"]:
        made += 1
        write_records(out / "real_payloads_video_1frame.bin",
                      iter_png(src["ucf_png"]), F1_SZ, args.max_records, max_mb)
        made += 1
        write_records(out / "real_payloads_video_2frame.bin",
                      iter_concat(src["ucf_png"], 2), F2_SZ, args.max_records, max_mb)
        made += 1
        write_records(out / "real_payloads_video_4frame.bin",
                      iter_concat(src["ucf_png"], 4), F4_SZ, args.max_records, max_mb)
    else:
        print("  SKIP video files (no UCF-Crime PNG frames found)")

    print(f"Done. Wrote {made} payload file(s) to {out}")
    if made < 5:
        print("NOTE: some sources were not found. Point --datasets-root at the folder "
              "that contains the ton_iot / uci / edge_iiotset / ucf-crime data, or adjust "
              "the discovery globs in discover().", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
