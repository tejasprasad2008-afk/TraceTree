"""
Bridge: CIC-MalMem-2022 → TraceTree 10-Feature Vector (Normalized)

Maps CIC memory-dump features into TraceTree's feature space, then normalizes
the output to match TraceTree's native feature distributions (as defined by
the hand-crafted labeled_fixtures_original.csv).
"""

import csv
import math
import random
import shutil
from pathlib import Path


# ── Constants ──────────────────────────────────────────────────────────────── #

CIC_CSV_PATH = Path.home() / "Downloads" / "Obfuscated-MalMem2022.csv"
FIXTURES_PATH = Path(__file__).parent / "data" / "labeled_fixtures.csv"
BACKUP_PATH = Path(__file__).parent / "data" / "labeled_fixtures_original.csv"

SAMPLES_PER_CLASS = 2500
NOISE_SIGMA_FRACTION = 0.03  # 3% noise — lighter to preserve class separation
RNG_SEED = 42

TRACETREE_COLUMNS = [
    "package_name", "node_count", "edge_count", "network_conn_count",
    "file_read_count", "execve_count", "total_severity",
    "suspicious_network_count", "sensitive_file_count", "max_severity",
    "temporal_pattern_count", "is_malicious",
]

FEATURE_KEYS = [
    "node_count", "edge_count", "network_conn_count", "file_read_count",
    "execve_count", "total_severity", "suspicious_network_count",
    "sensitive_file_count", "max_severity", "temporal_pattern_count",
]

# Target ranges from TraceTree's actual feature space (labeled_fixtures_original.csv)
# Format: (benign_min, benign_max, malicious_min, malicious_max)
TRACETREE_RANGES = {
    "node_count":              (2, 8, 8, 40),
    "edge_count":              (1, 6, 8, 45),
    "network_conn_count":      (0, 1, 1, 10),
    "file_read_count":         (4, 25, 45, 300),
    "execve_count":            (1, 3, 3, 10),
    "total_severity":          (0, 4, 10, 70),
    "suspicious_network_count": (0, 0, 1, 5),
    "sensitive_file_count":    (0, 0, 1, 6),
    "max_severity":            (0, 2.5, 4, 12),
    "temporal_pattern_count":  (0, 0, 0, 4),
}


# ── Helpers ────────────────────────────────────────────────────────────────── #

def safe_float(row, key, default=0.0):
    try:
        val = row.get(key, default)
        return float(val) if val not in (None, "", "NA", "NaN") else default
    except (ValueError, TypeError):
        return default


def std_dev(values):
    n = len(values)
    if n < 2:
        return 0.0
    mean = sum(values) / n
    variance = sum((x - mean) ** 2 for x in values) / n
    return math.sqrt(variance)


def rescale(value, src_min, src_max, dst_min, dst_max):
    """Linearly rescale a value from source range to destination range."""
    if src_max == src_min:
        return (dst_min + dst_max) / 2.0
    normalized = (value - src_min) / (src_max - src_min)
    normalized = max(0.0, min(1.0, normalized))  # Clamp to [0, 1]
    return dst_min + normalized * (dst_max - dst_min)


# ── Feature Mapping ────────────────────────────────────────────────────────── #

def compute_raw_features(row):
    """Extract raw CIC-derived features before normalization."""
    return {
        "node_count": safe_float(row, "pslist.nproc"),
        "edge_count": safe_float(row, "pslist.nproc") + safe_float(row, "dlllist.ndlls") / 10.0,
        "network_conn_count": safe_float(row, "psxview.not_in_pslist") + safe_float(row, "psxview.not_in_eprocess_pool"),
        "file_read_count": safe_float(row, "handles.nfile"),
        "execve_count": safe_float(row, "pslist.nprocs64bit") + safe_float(row, "svcscan.process_services"),
        "total_severity": safe_float(row, "malfind.ninjections") * 5.0 + safe_float(row, "malfind.commitCharge") * 0.1,
        "suspicious_network_count": safe_float(row, "psxview.not_in_csrss_handles") + safe_float(row, "psxview.not_in_session"),
        "sensitive_file_count": safe_float(row, "ldrmodules.not_in_load") + safe_float(row, "ldrmodules.not_in_init"),
        "max_severity": safe_float(row, "malfind.protection") * 0.5 + safe_float(row, "malfind.uniqueInjections") * 2.0,
        "temporal_pattern_count": safe_float(row, "callbacks.nanonymous") + safe_float(row, "callbacks.ngeneric"),
        "is_malicious": 0 if row.get("Class", "").strip() == "Benign" else 1,
        "_category": row.get("Category", "unknown").strip().lower().replace(" ", "_"),
    }


# ── Main Pipeline ──────────────────────────────────────────────────────────── #

def main():
    random.seed(RNG_SEED)

    if not CIC_CSV_PATH.exists():
        raise FileNotFoundError("CIC dataset not found at {}".format(CIC_CSV_PATH))
    print("✔ Found CIC-MalMem-2022 at {}".format(CIC_CSV_PATH))

    # Back up
    if FIXTURES_PATH.exists() and not BACKUP_PATH.exists():
        shutil.copy2(FIXTURES_PATH, BACKUP_PATH)
        print("✔ Backed up original fixtures")

    # Read original
    original_rows = []
    if BACKUP_PATH.exists():
        with open(BACKUP_PATH, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                original_rows.append(row)
    print("✔ Loaded {} original fixture rows".format(len(original_rows)))

    # Read CIC
    print("⏳ Reading CIC-MalMem-2022...")
    benign_raw = []
    malicious_raw = []

    with open(CIC_CSV_PATH, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            feat = compute_raw_features(row)
            if feat["is_malicious"] == 0:
                benign_raw.append(feat)
            else:
                malicious_raw.append(feat)

    print("  → Benign: {}  Malicious: {}".format(len(benign_raw), len(malicious_raw)))

    # Compute per-class per-feature ranges from CIC data
    cic_ranges = {}
    for key in FEATURE_KEYS:
        benign_vals = [r[key] for r in benign_raw]
        mal_vals = [r[key] for r in malicious_raw]
        cic_ranges[key] = {
            "benign_min": min(benign_vals) if benign_vals else 0,
            "benign_max": max(benign_vals) if benign_vals else 1,
            "malicious_min": min(mal_vals) if mal_vals else 0,
            "malicious_max": max(mal_vals) if mal_vals else 1,
        }

    # Stratified sample
    benign_sample = random.sample(benign_raw, min(SAMPLES_PER_CLASS, len(benign_raw)))
    malicious_sample = random.sample(malicious_raw, min(SAMPLES_PER_CLASS, len(malicious_raw)))
    print("✔ Sampled {} benign + {} malicious".format(len(benign_sample), len(malicious_sample)))

    # Normalize to TraceTree ranges
    for sample in benign_sample:
        for key in FEATURE_KEYS:
            src_min = cic_ranges[key]["benign_min"]
            src_max = cic_ranges[key]["benign_max"]
            dst_min, dst_max = TRACETREE_RANGES[key][0], TRACETREE_RANGES[key][1]
            sample[key] = round(rescale(sample[key], src_min, src_max, dst_min, dst_max), 2)

    for sample in malicious_sample:
        for key in FEATURE_KEYS:
            src_min = cic_ranges[key]["malicious_min"]
            src_max = cic_ranges[key]["malicious_max"]
            dst_min, dst_max = TRACETREE_RANGES[key][2], TRACETREE_RANGES[key][3]
            sample[key] = round(rescale(sample[key], src_min, src_max, dst_min, dst_max), 2)

    all_sampled = benign_sample + malicious_sample

    # Add noise
    feature_stds = {}
    for key in FEATURE_KEYS:
        vals = [s[key] for s in all_sampled]
        feature_stds[key] = std_dev(vals)

    for sample in all_sampled:
        for key in FEATURE_KEYS:
            sigma = feature_stds[key] * NOISE_SIGMA_FRACTION
            noise = random.gauss(0, sigma) if sigma > 0 else 0.0
            sample[key] = round(max(0.0, sample[key] + noise), 2)

    print("✔ Normalized to TraceTree feature space + {}% noise".format(int(NOISE_SIGMA_FRACTION * 100)))

    # Assign names
    benign_counter = 0
    malicious_counter = 0
    for sample in all_sampled:
        cat = sample.pop("_category")
        prefix = "cic_benign" if sample["is_malicious"] == 0 else "cic_{}".format(cat)
        if sample["is_malicious"] == 0:
            benign_counter += 1
            sample["package_name"] = "{}_{}".format(prefix, str(benign_counter).zfill(4))
        else:
            malicious_counter += 1
            sample["package_name"] = "{}_{}".format(prefix, str(malicious_counter).zfill(4))

    # Write
    with open(FIXTURES_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=TRACETREE_COLUMNS)
        writer.writeheader()
        for row in original_rows:
            writer.writerow({k: row.get(k, "") for k in TRACETREE_COLUMNS})
        for sample in all_sampled:
            writer.writerow({k: sample.get(k, "") for k in TRACETREE_COLUMNS})

    total = len(original_rows) + len(all_sampled)
    print("\n" + "=" * 60)
    print("SUCCESS: {} rows written to {}".format(total, FIXTURES_PATH.name))
    print("  Original: {} | CIC benign: {} | CIC malicious: {}".format(
        len(original_rows), len(benign_sample), len(malicious_sample)))
    print("=" * 60)

    # Stats
    print("\n📊 Feature ranges (CIC-normalized to TraceTree space):")
    for key in FEATURE_KEYS:
        b_vals = [s[key] for s in benign_sample]
        m_vals = [s[key] for s in malicious_sample]
        print("  {:30s}  benign=[{:.1f}-{:.1f}]  malicious=[{:.1f}-{:.1f}]".format(
            key, min(b_vals), max(b_vals), min(m_vals), max(m_vals)))


if __name__ == "__main__":
    main()
