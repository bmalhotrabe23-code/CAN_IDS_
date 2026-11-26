# Lightweight Hybrid Intrusion Detection System for the Automotive CAN Bus

**Author:** Bhuvan Malhotra (bmalhotra_be23@thapar.edu)
**Course:** UCS762 – Cybersecurity for Mobility Systems, Thapar Institute of Engineering & Technology, Patiala

This project contains a Springer LNCS-format article and a Python proof-of-concept simulation. Together they show how a small, in-vehicle intrusion detection system (IDS) can catch CAN-bus attacks that rule-based and cloud-based commercial tools miss, especially the **masquerade** attack.

---

## The problem

Cars contain 70–100 Electronic Control Units (ECUs) that talk over the **CAN bus**. CAN has:

- **no authentication**: receivers can't tell who sent a message
- **no encryption**: anyone on the bus can read every message
- **broadcast**: every message reaches every ECU

An attacker who reaches the bus can inject fake messages. Commercial IDS products mostly rely on **expert rules and signatures** in the car, or on **machine learning in the cloud**. These approaches:

- miss attacks nobody has seen before
- check timing but not content
- are too slow to stop millisecond-scale attacks

## The solution

A three-layer **hybrid edge IDS** that runs on the car's gateway ECU:

| Layer | What it does | Catches |
|---|---|---|
| **L1 – Rules** | Flags unknown IDs and messages arriving faster than half their normal period | DoS, fuzzing, injection |
| **L2 – One-class autoencoder** | A 22→16→6→16→22 neural network trained on **normal traffic only**. A high reconstruction error means an unusual frame | Masquerade, unknown attacks |
| **L3 – Fusion + 2-of-3 filter** | Alarm = L1 OR filtered L2. A known ID raises an alarm only if 2 of its last 3 frames were flagged. Alerts are reported via AUTOSAR IdsM | Reduces false alarms |

The autoencoder has **956 parameters**, which is **under 1 kB** after 8-bit quantisation, and needs **896 multiply-accumulates** per frame.

---

## Folder contents

```
CAN_IDS_Article/
├── main.tex                  # The article (Springer LNCS, compile on Overleaf)
├── preview.pdf               # Approximate preview of the compiled article
├── README.md                 # This file
└── simulation/
    ├── can_ids_sim.py        # Proof-of-concept simulation (Python)
    └── results.json          # Results produced by the script
```

---

## Running the simulation

### Requirements
- Python 3.9 or newer
- NumPy and scikit-learn

```bash
pip install numpy scikit-learn
```

### Run
Before running, change the output path on **line 135** of `can_ids_sim.py` to a local file:

```python
json.dump(res, open("results.json", "w"), indent=1)
```

Then:

```bash
cd simulation
python can_ids_sim.py
```

It takes about a minute. Scikit-learn may print `ConvergenceWarning` messages; these are harmless.

### What the script does
1. **Builds a fake car:** 40 CAN IDs, each repeating every 10–100 ms with 2% timing jitter, on a 500 kbit/s bus (about 36% bus load).
2. **Generates payloads:** a rolling counter, slow sensor-like signals, noise and constant bytes.
3. **Injects five attacks** between seconds 6 and 14 of a 20-second recording:
   - **DoS**: flood of ID `0x000`
   - **Fuzzing**: random IDs and data
   - **Spoofing**: forged data on a real ID, added on top of the genuine frames
   - **Replay**: old genuine frames re-sent
   - **Masquerade**: the real ECU is silenced and forged frames are sent at the normal rate
4. **Extracts 22 features per frame:** ID, known-ID flag, time gaps (log scale), Hamming distance, counter check, 8 payload bytes and 8 byte-differences.
5. **Trains and runs four detectors:** rules only, a supervised MLP (trained on DoS and fuzzing only), the one-class autoencoder, and the hybrid.
6. **Scores each detector** with precision, recall, F1-score and false-positive rate. It also reports model size, latency and how false alarms are distributed.

---

## Results (synthetic data)

Frame-level F1-score, with recall in brackets:

| Attack | Rule layer | Supervised MLP | One-class AE | Hybrid (proposed) |
|---|---|---|---|---|
| DoS | 1.000 (1.00) | 1.000 (1.00) | 0.999 (1.00) | **1.000** (1.00) |
| Fuzzing | 0.991 (0.99) | 0.999 (1.00) | 0.988 (1.00) | 0.978 (0.99) |
| Spoofing | 0.275 (0.28) | 0.000 (0.00) | 0.664 (1.00) | 0.656 (0.99) |
| Replay | 1.000 (1.00) | 0.000 (0.00) | 0.596 (1.00) | 0.651 (1.00) |
| **Masquerade** | **0.000** (0.00) | **0.000** (0.00) | 0.678 (0.73) | **0.762** (0.69) |

**Key findings**
- Easy attacks (DoS, fuzzing) are caught by every method.
- The supervised model scores 0 on every attack it wasn't trained on.
- On masquerade, rules score **0**, while the hybrid reaches **F1 = 0.762** with a **0.03%** false-positive rate.
- Outside the attack windows, the autoencoder's false-positive rate was **0.05–0.08%**.

### How to read the metrics
- **Recall:** the share of attack frames that were caught.
- **Precision:** the share of alarms that were real attacks.
- **F1-score:** the balance of precision and recall (1 = perfect, 0 = useless).
- **FPR (false-positive rate):** the share of normal frames wrongly flagged.

---

## Compiling the article

1. Go to [Overleaf](https://www.overleaf.com) and choose **New Project → Upload Project**, or create a blank project and upload `main.tex`.
2. Set the compiler to **pdfLaTeX**. The Springer `llncs` class is already available on Overleaf.
3. Click **Recompile**.

`preview.pdf` was built with an approximate class, so the final page layout on Overleaf may differ slightly.

---

## Limitations
- The data is **synthetic**: the results show how the method behaves, not real-vehicle performance.
- The next step is evaluation on real datasets: **HCRL Car-Hacking** and **ROAD** (ORNL).
- An attacker who knows the model could craft adversarial payloads. Combining the model with clock-skew fingerprinting would help.
- The speed figure (about 10 µs per frame on a Cortex-M4-class MCU) is an **estimate from operation counts**, not a hardware measurement.
- Only classical CAN is covered. CAN-FD and automotive Ethernet are future work.
- The IDS **complements** AUTOSAR SecOC; it does not replace it (defence-in-depth, as expected by ISO/SAE 21434).

---

## Key references
- Verma et al., *A comprehensive guide to CAN IDS data and introduction of the ROAD dataset*, PLoS ONE 19(1), 2024
- Seo, Song, Kim, *GIDS: GAN based intrusion detection system for in-vehicle network*, PST 2018 (HCRL Car-Hacking dataset)
- Cho & Shin, *Fingerprinting electronic control units for vehicle intrusion detection*, USENIX Security 2016
- Miller & Valasek, *Remote exploitation of an unaltered passenger vehicle*, Black Hat USA 2015
- ISO/SAE 21434:2021, *Road vehicles – Cybersecurity engineering*

The full reference list is in `main.tex`.
