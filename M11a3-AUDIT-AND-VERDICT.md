# M11-a.3 Audit & Verdict — ARM64-DEBUG Cell

**Date**: 2026-08-17
**Status**: Audit complete. Documentation-only checkpoint.
**Scope**: Statistical audit of the M11-a.3 ARM64-DEBUG timing-linkability cell.
No production code, protocol spec, methodology, analysis code, keys, data,
Cargo.lock, CI workflows, or Git history was modified.

---

## 0. Summary

The M11-a.3 ARM64-DEBUG cell audit is complete. The original registered
result `knn3=0.2086, p=1.0` is **retracted** as an artifact of a structurally
broken estimator and an apples-to-oranges permutation null. Under the
**corrected proper k=3 LOO** estimator with a matched within-block permutation
null, the ARM64-DEBUG cell yields `accuracy=0.3559`,
`p≈0.0965` (global shuffle) / `p≈0.1007` (within-block shuffle) — not
statistically significant at α=0.05, and only +2.26 pp over the correct
3-class chance baseline (1/3). All six independent negative controls are
consistent with chance.

**Verdict: No statistically significant identity linkability detected in the
ARM64-DEBUG cell** under proper estimation.

The x86-64 RELEASE timing capture is formally deferred pending identification
of a native x86-64 Windows workstation (Colab investigated and found unsuitable;
see §6). The provenance-verified x86-64 RELEASE binary remains preserved and
untouched.

---

## 1. Audit scope and method

The audit was conducted as a **read-only statistical review** — no production
code, experiment data, or methodology was modified. Audit scripts
(`_audit.py`, `_audit_lite.py`) and diagnostic scripts (`_knn_diag.py`,
`_knn_null.py`) operated on copies of the analysis pipeline and the existing
ARM64-DEBUG feature data (`R:\pq-tunnel-lab\M11a\data\arm64-debug\`).

The audit reconstructed every estimator in `m11a1_link.py`, verified the
neighbor-label structure of the proper k=3 LOO, validated the permutation
procedure, checked preprocessing/leakage/normalization/folds/labels/balance,
and computed six independent negative controls.

---

## 2. The retracted result

### Registered result (invalid)
```
knn3 = 0.2086, p = 1.0
```

### Three linked defects (not independent)

**Defect 1 — Incoherent primary estimator (`loo_knn`, `m11a1_link.py:57-68`).**

The `loo_knn(D, y, k=3)` function contains:

```python
nn = np.argsort(D, axis=1)[:, :k]      # selects 3 nearest INCLUDING self (D diagonal not set to inf)
votes = [y[j] for j in nn[i] if j != i]  # line 59: self-filter -- DEAD CODE (overwritten)
votes = [y[j] for j in nn[i]]          # line 61: overwrites above; includes self
votes = [v for v in votes if True]     # no-op
c = Counter(votes)
c.subtract([y[i]])                    # subtract self label (if present)
top = c.most_common(1)[0][0]          # insertion-order tie-breaking -- incoherent
```

- The diagonal of `D` is **never set to `inf`**, so self is always in the top-3
  neighbors.
- Line 59's `if j != i` self-exclusion filter is **dead code** — immediately
  overwritten by line 61 which re-includes all neighbors including self.
- `c.subtract([y[i]])` removes one self-label from the count, so the vote is
  over **2 neighbors** (not 3), while the function calls itself "k=3."
- `most_common(1)` on ties returns the first-inserted key — dependent on
  `np.argsort`'s tie-breaking, not on any coherent rule.

Hand-verification at `i=5`: truth = `a`, 3NN (include-self) = `[c, a, a]`.
- Proper k=3 LOO: `Counter([c, a, a])` → `a` (correct).
- Buggy primary: votes over `[c, a]` → tie → `most_common` returns `c` by
  insertion order (wrong).

The original estimator disagrees with proper k=3 LOO on **137/930 rows
(14.7%)**.

**Defect 2 — Apples-to-oranges permutation null (`loo_knn_labels`).**

The permutation null uses a *different estimator* from the observed statistic:
it includes self in the top-3 vote with no subtract, voting over 3 neighbors
(2 + 1 self). This is not the same computation as the (buggy) observed
estimator, so `p=1.0` is meaningless — the null was generated under a different
estimator than the one being tested.

**Defect 3 — Global-shuffle permutation ignores block structure.**

The permutation null uses `rng.permutation(y)` (a global shuffle of all 930
labels). However, PCA1 ANOVA across the 62 blocks yields `F=1.99, p=1.8e-5`,
proving that **blocks are not exchangeable** under label shuffling. The global
shuffle is therefore mildly anti-conservative. A block-constrained shuffle
(within-block label permutation) gives `p≈0.1007` (slightly higher, as
expected).

---

## 3. Corrected primary estimator: proper k=3 LOO

The mathematically correct k=3 LOO for the 3-class ARM64-DEBUG dataset:

```python
np.fill_diagonal(D, np.inf)                     # self impossible
nn3 = np.argsort(D, axis=1)[:, :3]               # top-3, no self
knn3_pred = np.array([Counter(y[nn3[i]].tolist()).most_common(1)[0][0]
                      for i in range(n)])
```

This is the estimator already used correctly in `m11a_link.py:169-170`
(`knn3` in the main analysis engine). The audit verified it is
**bit-identical** to the corrected computation, and that the feature matrix
(`log1p` + `StandardScaler`, Euclidean distance on 12 wire-gap features) is
unchanged.

### Neighbor-label structure (proper k=3 LOO, 930 runs)
| Pattern | Count | Fraction |
|---|---|---|
| Unanimous 3-NN (majority is 3/3) | 93 | 10.0% |
| Exact 1-1-1 tie (no majority) | 206 | 22.2% |
| 2-1 split (weak majority) | 631 | 67.8% |

Majority class among 3-NN matches true label in only **35.59%** of runs.

### Chance baseline
- **Correct reference for 3-class kNN**: uniform guess = **1/3 ≈ 0.3333**
- ARM64-DEBUG proper k=3 LOO accuracy = **0.3559** = +0.0226 pp over chance
  (not the +0.334 pp that would be implied by the retracted estimate)
- The "7/27 ≈ 0.2593" baseline that appeared in some scripts is **wrong** for
  kNN — it applies only to independent fair categorical draws, not to
  nearest-neighbor majority voting.

---

## 4. ARM64-DEBUG result (proper k=3 LOO, designated primary)

### Primary statistic

| Statistic | Value |
|---|---|
| Proper k=3 LOO accuracy | **0.3559** (331/930) |
| Chance baseline (3-class uniform) | 0.3333 (1/3) |
| Cohen's h | +0.080 (small, near-zero) |
| Wilson 95% CI | [0.3246, 0.3884] — **includes 1/3** |
| Permutation null mean | ~0.333 |
| Permutation null 95th percentile | 0.373 |
| Observed vs. null | 0.3559 — **within null range** |

### Permutation p-values

| Permutation scheme | p-value | Notes |
|---|---|---|
| Global label shuffle (10k iters, rng seed 1) | **≈0.0965** | Anti-conservative (ignores blocks) |
| Within-block-constrained shuffle (10k iters) | **≈0.1007** | Blocks are non-exchangeable (F=1.99, p=1.8e-5); this is the matched null |

p ≈ 0.0965 / 0.1007 is **not significant** at α=0.05. The observed accuracy
falls inside the null distribution's range.

### Preprocessing and integrity checks (all PASS)
- **Feature leakage**: FEAT ∩ {forbidden} = ∅ — no run_index, wall_start_ms,
  packet_count, or block_idx in the 12 wire-gap features.
- **Class balance**: 310/310/310 (a/b/c) — exactly balanced.
- **Run index**: unique 0-929 — no duplicates, no gaps.
- **Scaling parity**: log1p + StandardScaler applied identically; max absolute
  difference between audit and reference = 0.0.
- **Corrupted exclusions**: m2rtt < 1 ms = family misalignment marker;
  excluded counts verified.

---

## 5. Six independent negative controls (all consistent with chance)

| # | Control | Method | Result | Chance | Verdict |
|---|---|---|---|---|---|
| 1 | Within-between separation | P(between > within) AUC | 0.499 | 0.50 | Consistent |
| 2 | Position lookup | identity = f(run_index % 3) | 0.333 | 1/3 | Consistent |
| 3 | Schedule prediction | predict schedule-identity from wire features | 0.355–0.359 | 1/3 | Consistent |
| 4 | Mutual information | MI(identity, run_index) | ≈0 | 0 | Consistent |
| 5 | ANOVA | m2rtt ~ identity | p ≈ 0.611 | — | Consistent |
| 6 | Feature correlations | |r| per identity vs. run_index | < 0.06 | 0 | Consistent |

**Apparatus oracle**: harness-only features (run_index + wall_start + rows +
block_idx) classified identity at chance level under logistic regression —
the measurement harness itself introduces no identity-correlated signal.

---

## 6. x86-64 RELEASE provenance — already completed, preserved

### Stage-1 build (verified, not re-run)

The x86-64 RELEASE provenance workflow (`.github/workflows/m11a3-provenance.yml`
on branch `m11a3-arm-crossover`, commit `509ecda`) already produced the
artifact. It is a **Stage-1 provenance-only workflow** — no timing capture.

| Field | Value |
|---|---|
| Runner | `windows-latest` (Azure VM, Windows Server 2025 x64) |
| Target triple | `x86_64-pc-windows-msvc` (native, no cross-compilation) |
| Profile | `release` (`--release --locked`) |
| rustc | `rustc 1.97.1` |
| Cargo.lock SHA-256 | `03D5C038992477D76BAB8AF9C45D6BBA941A6A85598ED97D6E3ACA0D07452923` |
| PE machine type | `AMD64(x64)` (0x8664) |
| Raw binary SHA-256 | `ECB37D946128747773F9CC837C8EBA954FD89AD3F980331E7AEAFAA9A9FFFF13` |
| `.text` SHA-256 | `1930225a56ca36239db72568f163f8e0b9c090a9e3fe35f7de6c5d31b2b025c4` (byte-identical across rebuilds) |
| Reproducible code | ✅ `.text` reproducible |

### Artifacts preserved (location, unmodified)
```
R:\pq-tunnel-lab\M11a\out\repro\x86-64-release-provenance\
├── provenance.json
├── pq-tunnel-x86-64-release.exe          (build 1)
├── pq-tunnel-x86-64-release-build2.exe   (build 2, .text comparison)
├── Cargo.lock
├── cargo-tree.txt
├── cargo-build-1.log
├── cargo-build-2.log
└── m11a3-stage1-summary.md
```

These were downloaded from the GitHub Actions artifact `m11a3-x64-release`
and copied to the repro area. They have **not been executed** for timing.

---

## 7. Colab investigation — unsuitable for the timing cell

**Verdict: C — unsuitable.** (Full analysis:
`_recovered/C__Users_Dhane_AppData_Local_Temp_opencodem11a3_colab-verdict.md.txt`)

### Why Colab cannot serve as the x86-64 timing capture environment

1. **OS incompatibility**: The provenance-verified binary is a Windows PE (`x86_64-pc-windows-msvc`). Colab runs Ubuntu Linux. Windows PE cannot execute natively.

2. **Wine64 translation-layer nondeterminism**: Wine64 can launch the binary, but introduces nondeterministic IPC/jitter into the exact code path being measured. The `t_us` timestamps are captured **in-process** via `std::time::Instant` inside `wirelog.rs` (fires on every UDP send). Under Wine, every Windows socket syscall crosses into the wineserver process (separate Unix process), and the `Instant::now()` timestamp is taken after that Wine-mediated syscall returns — baking wineserver jitter (tens to hundreds of µs, with ms-range spikes) directly into the timing data.

3. **Microsecond-scale signal swamped**: The experiment measures microsecond-scale inter-packet gaps on a 5.12 ms (195.3 pkt/s) cover grid. Wine+KVM jitter is at the same order as or larger than the entire signal window.

4. **OS confound**: Colab runs Linux; the ARM64-DEBUG baseline was captured on **Windows native** (Snapdragon X Elite). Wine+Linux+KVM is a different OS, kernel, scheduler, and timer subsystem than the baseline. This confounds OS with architecture in the 2×2 DEBUG-vs-RELEASE × x86-64-vs-ARM64 comparison. The cover-traffic clock itself is platform-specific (Windows `CREATE_WAITABLE_TIMER_HIGH_RESOLUTION` vs. Linux `timerfd` — see DESIGN_DECISIONS §D23).

5. **No native x86-64 Linux binary acceptable**: A Linux x86-64 binary compiled with wirelog instrumentation would run natively, but confounds OS with architecture (x64 cells on Linux, ARM64 cells on Windows). All four cells must use the same OS for a valid crossover.

6. **GPU irrelevant**: The experiment is pure CPU/Rust/network. No GPU crates in `Cargo.lock`. T4 provides no benefit.

### Runtime feasibility
930 runs × 15 s = ~3.88 hours of binary execution. Colab free tier allows up to 12 h, but the 90-minute idle timeout requires the browser tab to stay active for the entire duration. Wine prefix initialization and wineserver startup add per-run overhead, pushing total to 5–8 hours — marginal even on Pro (24 h limit).

---

## 8. x86-64 RELEASE timing capture — formally deferred

The x86-64 RELEASE timing cell (62 blocks × 15 runs = 930 runs) is **deferred**.
It requires:

- A **native x86-64 Windows workstation** (genuine Intel/AMD silicon, not
  emulation, not Wine+KVM)
- **Dedicated hardware** (no competing compute workload during the
  ~4-hour capture window; shared cloud VMs inject µs-scale scheduling jitter)
- **Stable CPU frequency** (performance power plan, frequency scaling
  disabled — the experiment is sensitive to cycle-level timing variance)
- The **same OS** (Windows) as all other cells to avoid confounding OS with
  architecture

The provenance-verified x86-64 RELEASE binary is **preserved and untouched**
at `R:\pq-tunnel-lab\M11a\out\repro\x86-64-release-provenance\`. No
provisioning attempt was made or will be made without explicit user
direction.

---

## 9. Scientific conclusion

**Under the corrected proper k=3 LOO estimator, no statistically significant
identity linkability is detected in the ARM64-DEBUG cell.**

- knn3 accuracy = 0.3559 (+2.26 pp over 3-class chance)
- p ≈ 0.0965 (global) / ≈0.1007 (within-block) — not significant at α=0.05
- Wilson 95% CI [0.3246, 0.3884] includes the chance baseline (1/3)
- All six independent negative controls are consistent with chance
- The original `knn3=0.2086, p=1.0` result is **retracted** as an artifact of
  a broken estimator and mismatched null

**Proper k=3 LOO with a within-block-constrained permutation null is the
designated primary test**, effective immediately.

The experiment does not prove "no possible timing side channel" — per the
project guardrail, "no signal at this N/arch" ≠ "no possible channel." The
x86-64 RELEASE crossover cell (the only missing corner of the 2×2 matrix)
remains to be captured on native x86-64 Windows hardware when such a host is
available.

---

## 10. What did NOT change

- **Production source code**: untouched
- **Protocol specification** (`PROTOCOL_SPEC.md`): untouched
- **Threat model** (`THREAT_MODEL.md`): untouched
- **Design decisions** (`DESIGN_DECISIONS.md`): untouched
- **Cargo.lock**: untouched (hash matches CI)
- **CI workflows** (`.github/workflows/`): untouched (`ci.yml` pristine;
  `m11a3-provenance.yml` on `m11a3-arm-crossover` branch as before)
- **Git history**: untouched
- **Keys**: untouched
- **ARM64-DEBUG capture data**: untouched (930 runs preserved at
  `R:\pq-tunnel-lab\M11a\data\arm64-debug\`)
- **x86-64 RELEASE binary**: untouched (preserved at repro path)
- **Analysis code** (`m11a1_link.py`, `m11a3_analysis.py`): untouched — the
  audit was read-only, using separate audit scripts

---

*This document is a checkpoint, not a production artifact. It is committed
to the working tree as a documentation file only. No build, experiment, or
host-provisioning action was taken in its creation.*
