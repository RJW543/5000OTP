"""Analysis pipeline for the synthetic benchmark runs.

Checks that every expected run is present, reduces each run to per-run
summaries, aggregates across repeats, compares ciphers with Kruskal-Wallis
and Dunn, checks the 5% equivalence margin is achievable, and writes figures.

    python analyse_synthetic.py --results <dir> --output <dir>
    python analyse_synthetic.py --results <dir> --gate-only

The CSV filenames carry cipher, KEM level and device but not the workload or
repeat number, and there is no rate column, so the workload is inferred from
the packet size and the packet rate measured over the first packets of a run.
"""

from __future__ import annotations

import argparse
import csv
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import stats


import re

FILENAME_RE = re.compile(
    r"results_(?P<system>.+?)_kem(?P<kem>768|1024)_"
    r"(?P<device>pi[0-9A-Za-z]+)_(?P<stamp>\d{8}_\d{6})\.csv$"
)

CIPHERS = ["AES-256-GCM", "ChaCha20-Poly1305", "SNOW-V-GCM", "Ascon-PRNG-XOR"]
DEVICES = ["pi0", "pi5"]
KEMS = ["768", "1024"]
REPEATS = 30

WARMUP_NS = 10_000_000_000
MEASURE_SECONDS = 60.0
RATE_PROBE_PACKETS = 31

ALPHA = 0.05
EQUIV_MARGIN_PCT = 5.0

# Physical ceiling on process CPU%: it cannot exceed (core count) * 100.  Both
# target devices are quad-core (Pi 5 Cortex-A76, Pi Zero 2 W Cortex-A53), so
# 400%.  Per-second samples above this are kernel CPU-time / clock accounting
# glitches, and are dropped before computing mean and peak CPU.
CPU_CEILING_PCT = 400.0

COL_TS = "timestamp_ns"
COL_PID = "packet_id"
COL_BYTES = "plaintext_bytes"
COL_ENC = "encrypt_ns"
COL_DEC = "decrypt_ns"
COL_CPU = "cpu_pct"
COL_RSS = "rss_kb"
COL_TEMP = "temp_c"
COL_SRC = "payload_source"
COL_KEM_ENC = "kem_encaps_ns"
COL_KEM_DEC = "kem_decaps_ns"
COL_KEM_PRE = "kem_pre_rss_kb"
COL_KEM_POST = "kem_post_rss_kb"
THROTTLE_LIMIT_C = 80.0

RATE_TARGETS = {
    512: {0.10: "telemetry_nbiot", 0.50: "telemetry_ltem"},
    16384: {0.62: "video_low_10fps", 1.85: "video_mean_30fps",
            2.65: "video_p95_30fps", 2.69: "video_stress_max"},
    32768: {1.85: "video_mean_2frame", 2.65: "video_p95_2frame",
            2.69: "video_stress_2frame"},
    65536: {1.85: "video_mean_4frame", 2.65: "video_p95_4frame",
            2.69: "video_stress_4frame"},
}
SAT_NAME = {512: "sat_512", 16384: "sat_16384",
            32768: "sat_32768", 65536: "sat_65536"}

RATE_CORE = ["telemetry_nbiot", "telemetry_ltem", "video_low_10fps",
             "video_mean_30fps", "video_p95_30fps", "video_stress_max"]
BUNDLING = ["video_mean_2frame", "video_p95_2frame", "video_stress_2frame",
            "video_mean_4frame", "video_p95_4frame", "video_stress_4frame"]
SATURATION = ["sat_512", "sat_16384", "sat_32768", "sat_65536"]
ALL_WORKLOADS = RATE_CORE + BUNDLING + SATURATION


def campaign_of(workload: str) -> str:
    if workload in BUNDLING:
        return "bundling"
    if workload in SATURATION:
        return "saturation"
    return "rate_core"


def probe_rate(path: Path):
    """Read enough of a file to get its packet size and rate (Mbps)."""
    ts, b = [], None
    with open(path, newline="") as fh:
        rd = csv.reader(fh)
        next(rd, None)
        for row in rd:
            if len(row) < 3 or row[1] == "-1":
                continue
            try:
                t, bb = int(row[0]), int(row[2])
            except ValueError:
                continue
            b = bb
            ts.append(t)
            if len(ts) >= RATE_PROBE_PACKETS:
                break
    if b is None or len(ts) < 2:
        return b, None, len(ts)
    dt = ts[-1] - ts[0]
    rate = (len(ts) - 1) * b * 8 / (dt / 1e9) / 1e6 if dt > 0 else None
    return b, rate, len(ts)


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


def discover(results_root: Path):
    records, unparseable, unclassified, short = [], [], [], []
    for path in sorted(results_root.rglob("*.csv")):
        m = FILENAME_RE.search(path.name)
        if not m:
            unparseable.append(path)
            continue
        b, rate, npk = probe_rate(path)
        if npk < 2:
            short.append(path)
            continue
        wl = classify(b, rate)
        if wl is None:
            unclassified.append((path, b, rate))
            continue
        records.append({
            "path": str(path), "device": m["device"], "system": m["system"],
            "kem": m["kem"], "workload": wl, "campaign": campaign_of(wl),
            "packet_bytes": b, "probe_rate_mbps": rate,
        })
    return records, unparseable, unclassified, short


def expected_cells(devices, ciphers, kems):
    return {(d, c, k, w)
            for d in devices for c in ciphers for k in kems for w in ALL_WORKLOADS}


def completeness_report(records, devices, ciphers, kems, out_dir,
                        unparseable, unclassified, short):
    counts = Counter((r["device"], r["system"], r["kem"], r["workload"])
                     for r in records)
    expected = expected_cells(devices, ciphers, kems)

    lines = ["=" * 70, "COMPLETENESS + INTEGRITY GATE", "=" * 70]
    lines.append(f"CSV files classified : {len(records)}")
    lines.append(f"Expected runs        : {len(expected) * REPEATS}")
    lines.append(f"Unparseable names    : {len(unparseable)}")
    lines.append(f"Unclassified runs    : {len(unclassified)}")
    lines.append(f"Too short to probe   : {len(short)}")
    lines.append("")

    lines.append("Runs found per device / cipher / kem (expect "
                 f"{len(ALL_WORKLOADS) * REPEATS}):")
    for d in devices:
        for c in ciphers:
            for k in kems:
                got = sum(v for (dd, cc, kk, _), v in counts.items()
                          if (dd, cc, kk) == (d, c, k))
                exp = len(ALL_WORKLOADS) * REPEATS
                flag = "OK" if got == exp else "<-- short" if got < exp else "<-- surplus"
                lines.append(f"  {d:<5} {c:<18} kem{k:<5} {got:>4} / {exp:<4} {flag}")
    lines.append("")

    short_cells = []
    for cell in sorted(expected):
        got = counts.get(cell, 0)
        if got != REPEATS:
            short_cells.append((cell, got))
    if short_cells:
        lines.append(f"Cells not at {REPEATS} repeats ({len(short_cells)}):")
        for (d, c, k, w), got in short_cells[:80]:
            lines.append(f"  {d:<5} {c:<18} kem{k:<5} {w:<20} {got}/{REPEATS}")
        if len(short_cells) > 80:
            lines.append(f"  ... and {len(short_cells) - 80} more (see "
                         "missing_cells.csv)")
        lines.append("")

    if unclassified:
        lines.append(f"Unclassified runs ({len(unclassified)}), first 20:")
        for path, b, rate in unclassified[:20]:
            rs = f"{rate:.2f}" if rate is not None else "NA"
            lines.append(f"  bytes={b} rate={rs}  {Path(path).name}")
        lines.append("")
    if unparseable:
        lines.append(f"Unparseable names ({len(unparseable)}), first 20:")
        for p in unparseable[:20]:
            lines.append(f"  {p.name}")
        lines.append("")

    cellmap = defaultdict(list)
    for r in records:
        cellmap[(r["device"], r["system"], r["kem"], r["workload"])].append(r["path"])
    surplus = []
    for paths in cellmap.values():
        if len(paths) > REPEATS:
            surplus.extend(sorted(paths)[REPEATS:])
    if surplus:
        lines.append(f"Surplus runs beyond {REPEATS}, candidates to delete ({len(surplus)}):")
        for p in surplus[:40]:
            lines.append(f"  {Path(p).name}")
        lines.append("")
    if short:
        lines.append(f"Unreadable / too short ({len(short)}):")
        for p in short[:40]:
            lines.append(f"  {Path(p).name}")
        lines.append("")
    report = "\n".join(lines)
    print(report)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "completeness_report.txt").write_text(report)
    if short_cells:
        pd.DataFrame([{"device": d, "system": c, "kem": k, "workload": w,
                       "found": got, "expected": REPEATS}
                      for (d, c, k, w), got in short_cells]).to_csv(
            out_dir / "missing_cells.csv", index=False)

    return not short_cells and not unparseable and not unclassified and not short


def reduce_run(rec, integrity):
    path = rec["path"]
    try:
        df = pd.read_csv(path)
    except Exception as exc:
        integrity.append(f"UNREADABLE {path}: {exc}")
        return None
    if df.empty:
        integrity.append(f"EMPTY {path}")
        return None

    if COL_SRC in df.columns:
        srcs = set(df[COL_SRC].dropna().astype(str).unique())
        if srcs - {"synthetic"}:
            integrity.append(f"NON-SYNTHETIC payload_source in {path}: {srcs}")

    kem_row = None
    if COL_PID in df.columns:
        mask = df[COL_PID] == -1
        if mask.any():
            kem_row = df[mask].iloc[0]
        pkt = df[~mask].copy()
    else:
        pkt = df.copy()

    if COL_TS in pkt.columns and not pkt.empty:
        t0 = pkt[COL_TS].min()
        pkt = pkt[pkt[COL_TS] >= t0 + WARMUP_NS]
    if pkt.empty:
        integrity.append(f"NO POST-WARMUP ROWS {path}")
        return None

    max_temp = np.nan
    if COL_TEMP in pkt.columns:
        temp = pd.to_numeric(pkt[COL_TEMP], errors="coerce")
        tmax = temp[temp > 0].max()
        if pd.notna(tmax):
            max_temp = float(tmax)
            if tmax > THROTTLE_LIMIT_C:
                integrity.append(
                    f"TEMP {tmax:.1f}C > {THROTTLE_LIMIT_C}C (throttle risk) {path}")

    out = {k: rec[k] for k in ("device", "system", "kem", "workload", "campaign")}
    out["max_temp_c"] = max_temp

    bytes_val = (pd.to_numeric(pkt[COL_BYTES], errors="coerce").dropna().iloc[0]
                 if COL_BYTES in pkt.columns and not pkt[COL_BYTES].dropna().empty
                 else np.nan)
    out["packet_bytes"] = bytes_val
    out["n_packets_postwarmup"] = len(pkt)
    out["throughput_mbps"] = (len(pkt) * bytes_val * 8 / (MEASURE_SECONDS * 1e6)
                              if not math.isnan(bytes_val) else np.nan)

    for col, tag in ((COL_ENC, "encrypt"), (COL_DEC, "decrypt")):
        if col in pkt.columns:
            v = pd.to_numeric(pkt[col], errors="coerce").dropna()
            if len(v):
                out[f"median_{tag}_ns"] = float(v.median())
                out[f"mean_{tag}_ns"] = float(v.mean())
                out[f"p95_{tag}_ns"] = float(v.quantile(0.95))
                out[f"p99_{tag}_ns"] = float(v.quantile(0.99))
    if "median_encrypt_ns" in out and not math.isnan(bytes_val) and bytes_val:
        out["median_perbyte_ns"] = out["median_encrypt_ns"] / bytes_val

    if COL_CPU in pkt.columns:
        cpu = pd.to_numeric(pkt[COL_CPU], errors="coerce")
        cpu = cpu[cpu > 0]
        # Drop non-physical readings before aggregating: a value above the
        # core-count ceiling is a sampler glitch, not real load (one such
        # sample was observed on the Pi Zero 2 W under peak Ascon load).
        cpu = cpu[cpu <= CPU_CEILING_PCT]
        if len(cpu):
            out["mean_cpu_pct"] = float(cpu.mean())
            out["peak_cpu_pct"] = float(cpu.max())

    if COL_RSS in pkt.columns:
        rss = pd.to_numeric(pkt[COL_RSS], errors="coerce")
        rss = rss[rss > 0]
        if len(rss):
            out["peak_rss_kb"] = float(rss.max())
            out["mean_rss_kb"] = float(rss.mean())
            out["rss_delta_kb"] = float(rss.max() - rss.iloc[0])

    if kem_row is not None:
        for c, k in ((COL_KEM_ENC, "kem_encaps_ns"), (COL_KEM_DEC, "kem_decaps_ns"),
                     (COL_KEM_PRE, "kem_pre_rss_kb"), (COL_KEM_POST, "kem_post_rss_kb")):
            if c in kem_row.index:
                out[k] = pd.to_numeric(kem_row[c], errors="coerce")
        if "kem_post_rss_kb" in out and "kem_pre_rss_kb" in out:
            out["kem_rss_delta_kb"] = out["kem_post_rss_kb"] - out["kem_pre_rss_kb"]

    return out


def reduce_saturation(rec, integrity):
    path = rec["path"]
    bytes_val = rec.get("packet_bytes")
    t0 = None
    count = 0
    maxtemp = 0.0
    try:
        with open(path, newline="") as fh:
            next(fh, None)
            for line in fh:
                parts = line.split(",")
                if len(parts) < 11 or parts[1] == "-1":
                    continue
                try:
                    ts = int(parts[0])
                except ValueError:
                    continue
                if t0 is None:
                    t0 = ts
                if ts >= t0 + WARMUP_NS:
                    count += 1
                tc = parts[9]
                if tc not in ("0", "0.0", "0.00"):
                    try:
                        v = float(tc)
                        if v > maxtemp:
                            maxtemp = v
                    except ValueError:
                        pass
    except Exception as exc:
        integrity.append(f"UNREADABLE {path}: {exc}")
        return None
    if t0 is None or count == 0:
        integrity.append(f"NO POST-WARMUP ROWS {path}")
        return None
    if maxtemp > THROTTLE_LIMIT_C:
        integrity.append(f"TEMP {maxtemp:.1f}C > {THROTTLE_LIMIT_C}C (throttle risk) {path}")
    out = {k: rec[k] for k in ("device", "system", "kem", "workload", "campaign")}
    out["packet_bytes"] = bytes_val
    out["n_packets_postwarmup"] = count
    out["throughput_mbps"] = (count * bytes_val * 8 / (MEASURE_SECONDS * 1e6)
                              if bytes_val else float("nan"))
    out["max_temp_c"] = maxtemp if maxtemp > 0 else float("nan")
    return out


def build_perrun(records, out_dir):
    integrity, rows = [], []
    total = len(records)
    for i, rec in enumerate(records, 1):
        if rec["campaign"] == "saturation":
            r = reduce_saturation(rec, integrity)
        else:
            r = reduce_run(rec, integrity)
        if r is not None:
            rows.append(r)
        print(f"[{i}/{total}] done {Path(rec['path']).name}  ({total - i} left)", flush=True)
    perrun = pd.DataFrame(rows)
    out_dir.mkdir(parents=True, exist_ok=True)
    perrun.to_csv(out_dir / "per_run_metrics.csv", index=False)
    if integrity:
        (out_dir / "integrity_warnings.txt").write_text("\n".join(integrity))
        print(f"[integrity] {len(integrity)} warning(s) -> "
              f"{out_dir/'integrity_warnings.txt'}")
    print(f"[reduce] {len(perrun)} runs reduced -> {out_dir/'per_run_metrics.csv'}")
    return perrun


GROUP = ["device", "campaign", "system", "kem", "workload"]
AGG_METRICS = ["throughput_mbps", "median_encrypt_ns", "mean_encrypt_ns",
               "p95_encrypt_ns", "p99_encrypt_ns", "median_perbyte_ns",
               "median_decrypt_ns", "mean_cpu_pct", "peak_cpu_pct",
               "peak_rss_kb", "mean_rss_kb", "rss_delta_kb",
               "kem_encaps_ns", "kem_decaps_ns", "kem_rss_delta_kb"]


def bootstrap_ci(vals, ci=0.95, n_boot=10000, rng=None):
    rng = rng or np.random.default_rng(12345)
    if len(vals) < 2:
        return (np.nan, np.nan)
    means = rng.choice(vals, size=(n_boot, len(vals)), replace=True).mean(axis=1)
    return (float(np.percentile(means, (1 - ci) / 2 * 100)),
            float(np.percentile(means, (1 + ci) / 2 * 100)))


def aggregate(perrun, out_dir):
    recs = []
    metrics = [m for m in AGG_METRICS if m in perrun.columns]
    for keys, g in perrun.groupby(GROUP):
        base = dict(zip(GROUP, keys))
        for m in metrics:
            v = g[m].dropna().to_numpy()
            if len(v) == 0:
                continue
            n = len(v)
            mean = float(np.mean(v))
            sd = float(np.std(v, ddof=1)) if n > 1 else 0.0
            normal = True
            if n >= 3 and np.ptp(v) > 0:
                try:
                    normal = stats.shapiro(v).pvalue >= 0.05
                except Exception:
                    normal = True
            if normal and n > 1:
                hw = stats.t.ppf(0.975, n - 1) * sd / math.sqrt(n)
                lo, hi, method = mean - hw, mean + hw, "t"
            else:
                lo, hi = bootstrap_ci(v)
                method = "bootstrap"
            recs.append(dict(base, metric=m, n=n, mean=mean, sd=sd,
                             ci_lo=lo, ci_hi=hi, ci_method=method,
                             cv_pct=(100 * sd / mean) if mean else np.nan))
    agg = pd.DataFrame(recs)
    agg.to_csv(out_dir / "aggregated_metrics.csv", index=False)
    print(f"[aggregate] {len(agg)} (config x metric) rows -> "
          f"{out_dir/'aggregated_metrics.csv'}")
    return agg


def dunn_bonferroni(groups):
    names = list(groups)
    allv = np.concatenate([groups[n] for n in names])
    ranks = stats.rankdata(allv)
    _, counts = np.unique(allv, return_counts=True)
    ties = np.sum(counts**3 - counts)
    N = len(allv)
    sizes, mean_ranks, idx = {}, {}, 0
    for n in names:
        k = len(groups[n])
        sizes[n] = k
        mean_ranks[n] = ranks[idx:idx + k].mean()
        idx += k
    sigma2 = (N * (N + 1) / 12) - ties / (12 * (N - 1))
    m = len(names) * (len(names) - 1) // 2
    out = []
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            a, b = names[i], names[j]
            se = math.sqrt(sigma2 * (1 / sizes[a] + 1 / sizes[b]))
            z = (mean_ranks[a] - mean_ranks[b]) / se if se else 0.0
            p = 2 * (1 - stats.norm.cdf(abs(z)))
            out.append(dict(a=a, b=b, z=z, p_unadj=p,
                            p_bonferroni=min(1.0, p * m)))
    return out


def epsilon_squared(H, N):
    return H * (N + 1) / (N**2 - 1) if N > 1 else np.nan


CROSS_TESTS = [
    ("saturation", "throughput_mbps"),
    ("rate_core", "median_encrypt_ns"),
    ("rate_core", "median_perbyte_ns"),
    ("bundling", "median_encrypt_ns"),
]


def cross_system(perrun, out_dir):
    kw_rows, dunn_rows = [], []
    for campaign, metric in CROSS_TESTS:
        if metric not in perrun.columns:
            continue
        sub = perrun[(perrun.campaign == campaign) & perrun[metric].notna()]
        if sub.empty:
            continue
        for (device, kem, workload), g in sub.groupby(["device", "kem", "workload"]):
            groups = {s: gg[metric].to_numpy()
                      for s, gg in g.groupby("system") if len(gg) >= 2}
            if len(groups) < 2:
                continue
            N = sum(len(v) for v in groups.values())
            allv = np.concatenate(list(groups.values()))
            if np.ptp(allv) == 0:
                kw_rows.append(dict(campaign=campaign, metric=metric, device=device,
                                    kem=kem, workload=workload, n_systems=len(groups),
                                    H=np.nan, p=np.nan, epsilon_sq=np.nan,
                                    significant=False, note="identical values"))
                continue
            H, p = stats.kruskal(*groups.values())
            kw_rows.append(dict(campaign=campaign, metric=metric, device=device,
                                kem=kem, workload=workload, n_systems=len(groups),
                                H=H, p=p, epsilon_sq=epsilon_squared(H, N),
                                significant=p < ALPHA, note=""))
            if p < ALPHA:
                for d in dunn_bonferroni(groups):
                    d.update(campaign=campaign, metric=metric, device=device,
                             kem=kem, workload=workload)
                    dunn_rows.append(d)
    pd.DataFrame(kw_rows).to_csv(out_dir / "kruskal_wallis.csv", index=False)
    pd.DataFrame(dunn_rows).to_csv(out_dir / "dunn_posthoc.csv", index=False)
    print(f"[cross-cipher] {len(kw_rows)} KW tests, {len(dunn_rows)} Dunn pairs -> "
          f"{out_dir/'kruskal_wallis.csv'}")


FEASIBILITY = [
    ("saturation", "throughput_mbps"),
    ("rate_core", "median_encrypt_ns"),
    ("rate_core", "mean_cpu_pct"),
    ("rate_core", "peak_rss_kb"),
]


def feasibility_check(perrun, out_dir):
    rows = []
    for campaign, metric in FEASIBILITY:
        if metric not in perrun.columns:
            continue
        sub = perrun[(perrun.campaign == campaign) & perrun[metric].notna()]
        for keys, g in sub.groupby(GROUP):
            v = g[metric].to_numpy()
            n = len(v)
            if n < 2 or v.mean() == 0:
                continue
            hw = stats.t.ppf(0.95, n - 1) * np.std(v, ddof=1) / math.sqrt(n)
            rows.append(dict(zip(GROUP, keys)) | dict(
                metric=metric, n=n, mean=v.mean(),
                ci90_halfwidth_pct=100 * hw / v.mean()))
    fdf = pd.DataFrame(rows)
    if fdf.empty:
        print("[feasibility] no data")
        return
    fdf["exceeds_margin"] = fdf["ci90_halfwidth_pct"] > EQUIV_MARGIN_PCT
    fdf.to_csv(out_dir / "feasibility_check.csv", index=False)
    print("\n" + "=" * 70)
    print(f"EQUIVALENCE-MARGIN FEASIBILITY (margin = +/-{EQUIV_MARGIN_PCT}%)")
    print("=" * 70)
    for metric, w in fdf.groupby("metric")["ci90_halfwidth_pct"].max().items():
        verdict = "OK" if w <= EQUIV_MARGIN_PCT else "too tight, widen margin"
        print(f"  {metric:<22} worst 90% CI half-width = {w:5.2f}%   {verdict}")
    bad = fdf[fdf.exceeds_margin]
    if len(bad):
        print(f"\n  {len(bad)} config(s) exceed the margin (see feasibility_check.csv).")
    print()


def make_figures(perrun, out_dir):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception as exc:
        print(f"[figures] matplotlib unavailable, skipping: {exc}")
        return
    fig_dir = out_dir / "figures"
    fig_dir.mkdir(parents=True, exist_ok=True)

    def save(fig, name):
        fig.tight_layout()
        fig.savefig(fig_dir / name, dpi=130)
        plt.close(fig)

    sat = perrun[perrun.campaign == "saturation"]
    for device, gd in sat.groupby("device"):
        piv = gd.pivot_table(index="packet_bytes", columns="system",
                             values="throughput_mbps", aggfunc="mean")
        if piv.empty:
            continue
        fig, ax = plt.subplots(figsize=(8, 4.5))
        piv.plot.bar(ax=ax)
        ax.set(title=f"Saturation throughput - {device}", ylabel="Mbps",
               xlabel="packet bytes")
        save(fig, f"throughput_{device}.png")

    rc = perrun[perrun.campaign == "rate_core"]
    for metric, fname, ylab in (("median_encrypt_ns", "latency", "ns"),
                                ("peak_rss_kb", "rss", "kB")):
        if metric not in rc.columns:
            continue
        for device, gd in rc.groupby("device"):
            data, labels = [], []
            for s, gs in gd.groupby("system"):
                vals = gs[metric].dropna().to_numpy()
                if len(vals):
                    data.append(vals)
                    labels.append(s)
            if not data:
                continue
            fig, ax = plt.subplots(figsize=(7, 4.5))
            ax.boxplot(data)
            ax.set_xticks(range(1, len(labels) + 1))
            ax.set_xticklabels(labels, rotation=20, ha="right")
            ax.set(title=f"{metric} - {device}", ylabel=ylab)
            save(fig, f"{fname}_{device}.png")

    print(f"[figures] written -> {fig_dir}")


def cap_to_repeats(records):
    by = defaultdict(list)
    for r in records:
        by[(r["device"], r["system"], r["kem"], r["workload"])].append(r)
    kept, dropped = [], []
    for rs in by.values():
        rs = sorted(rs, key=lambda r: r["path"])
        kept.extend(rs[:REPEATS])
        dropped.extend(rs[REPEATS:])
    return kept, dropped


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--results", required=True, type=Path)
    ap.add_argument("--output", type=Path, default=Path("analysis_output"))
    ap.add_argument("--devices", nargs="+", default=DEVICES)
    ap.add_argument("--ciphers", nargs="+", default=CIPHERS)
    ap.add_argument("--kems", nargs="+", default=KEMS)
    ap.add_argument("--gate-only", action="store_true",
                    help="run only the completeness/integrity check")
    ap.add_argument("--force", action="store_true",
                    help="run the analysis even if the gate fails")
    ap.add_argument("--no-figures", action="store_true")
    args = ap.parse_args(argv)

    if not args.results.exists():
        sys.exit(f"results directory not found: {args.results}")
    args.output.mkdir(parents=True, exist_ok=True)

    print(f"Scanning {args.results} for CSV files ...", flush=True)
    records, unparseable, unclassified, short = discover(args.results)
    if len(records)+len(unparseable)+len(unclassified)+len(short) == 0:
        sys.exit(f"No CSV files found under {args.results}")
    complete = completeness_report(records, args.devices, args.ciphers, args.kems,
                                   args.output, unparseable, unclassified, short)

    if args.gate_only:
        return 0 if complete else 1
    if not complete and not args.force:
        print("GATE FAILED: data set is not complete (see report above).")
        print("Fix the gaps, or re-run with --force to analyse what is present.")
        return 1
    if not complete:
        print("GATE FAILED but --force given: continuing with available runs.\n")
    if not records:
        sys.exit("No runs to analyse.")

    records, dropped = cap_to_repeats(records)
    if dropped:
        pd.DataFrame([{"device": r["device"], "system": r["system"], "kem": r["kem"],
                       "workload": r["workload"], "path": r["path"]} for r in dropped]
                     ).to_csv(args.output / "dropped_runs.csv", index=False)
        print(f"[trim] capped to {REPEATS} per cell; dropped {len(dropped)} surplus")
    perrun = build_perrun(records, args.output)
    if perrun.empty:
        sys.exit("All runs rejected during reduction; see integrity_warnings.txt")
    aggregate(perrun, args.output)
    cross_system(perrun, args.output)
    feasibility_check(perrun, args.output)
    if not args.no_figures:
        make_figures(perrun, args.output)

    print(f"\nDone. Outputs in {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
