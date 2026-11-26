"""Synthetic CAN-bus IDS proof of concept.
Generates periodic CAN traffic, injects DoS / fuzzing / spoofing / replay attacks,
and compares (a) a rule-based IDS (ID whitelist + frequency threshold, the style
used by signature/rule products) with (b) a supervised tiny MLP and
(c) a one-class autoencoder trained only on normal traffic.
All data is synthetic; results illustrate the method, not a real vehicle."""
import numpy as np, time, json
from sklearn.neural_network import MLPClassifier, MLPRegressor
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import precision_recall_fscore_support

rng = np.random.default_rng(42)
N_IDS = 40
ids = np.sort(rng.choice(np.arange(0x080, 0x7FF), N_IDS, replace=False))
periods = rng.choice([0.010, 0.020, 0.050, 0.100], N_IDS)  # seconds
BIT_T = 1 / 500e3; FRAME_T = 111 * BIT_T  # 500 kbit/s, ~111 bits/frame

def payload(k, t, cnt):
    """Deterministic-ish signals: counter, slow sinusoid, constant bytes, small noise."""
    p = np.zeros(8, dtype=np.uint8)
    p[0] = cnt % 16
    p[1] = int(127 + 100 * np.sin(2 * np.pi * t / (2 + k % 5))) & 0xFF
    p[2] = (k * 37) & 0xFF
    p[3] = int(60 + 20 * np.sin(2 * np.pi * t / 7) + rng.normal(0, 1)) & 0xFF
    p[4:] = (k * 11 + np.arange(4)) & 0xFF
    return p

def normal_traffic(T):
    frames = []
    for k, (i, per) in enumerate(zip(ids, periods)):
        t = rng.uniform(0, per); c = 0
        while t < T:
            frames.append((t + rng.normal(0, per * 0.02), i, payload(k, t, c), 0, 0)); t += per; c += 1
    return sorted(frames, key=lambda f: f[0])

def inject(frames, T, kind):
    t0, t1 = T * 0.3, T * 0.7; atk = []
    if kind == 1:   # DoS: highest-priority ID flood
        t = t0
        while t < t1: atk.append((t, 0x000, np.zeros(8, np.uint8), 1, 1)); t += 0.0003
    elif kind == 2: # Fuzzing: random IDs and payloads
        t = t0
        while t < t1: atk.append((t, int(rng.integers(0, 0x7FF)), rng.integers(0, 256, 8).astype(np.uint8), 1, 2)); t += 0.0008
    elif kind == 3: # Spoofing: legit ID, legit rate, forged constant payload (e.g. RPM/gear)
        k = 5; i = ids[k]; t = t0
        while t < t1:
            p = payload(k, t, 0); p[1] = 0xFF; p[3] = 0x00; p[0] = 0
            atk.append((t + 0.001, i, p, 1, 3)); t += periods[k]
    elif kind == 4: # Replay: earlier legit frames of one ID re-sent at normal rate
        k = 9; i = ids[k]; old = [f for f in frames if f[1] == i and f[0] < t0 * 0.5]; t = t0; j = 0
        while t < t1 and old:
            atk.append((t + 0.0007, i, old[j % len(old)][2].copy(), 1, 4)); t += periods[k]; j += 1
    elif kind == 5: # Masquerade: legit sender silenced (e.g. bus-off), attacker sends forged payload at nominal rate
        k = 12; i = ids[k]
        frames = [f for f in frames if not (f[1] == i and t0 <= f[0] < t1)]
        t = t0; c = 0
        while t < t1:
            p = payload(k, t, c); p[3] = (p[3] + 90) & 0xFF; p[1] = 0x10
            atk.append((t + rng.normal(0, periods[k] * 0.02), i, p, 1, 5)); t += periods[k]; c += 1
    return sorted(frames + atk, key=lambda f: f[0])

def features(frames):
    """Per-frame features computable on an ECU in O(1) memory per ID."""
    last_t, last_p, last_any = {}, {}, None; X = []
    known = set(ids.tolist())
    for t, i, p, y, a in frames:
        dt_id = t - last_t.get(i, t - 1.0)
        dt_any = 0.0 if last_any is None else t - last_any
        prev = last_p.get(i, p)
        ham = int(np.unpackbits(np.bitwise_xor(p, prev)).sum())
        cnt_ok = float(((int(prev[0]) + 1) % 16) == int(p[0]))
        X.append([i / 0x7FF, float(i in known), np.log10(max(dt_id, 0) + 1e-5), np.log10(max(dt_any, 0) + 1e-5), ham / 64, cnt_ok,
                  *(p / 255.0), *((p.astype(int) - prev.astype(int)) / 255.0)])
        last_t[i], last_p[i], last_any = t, p, t
    return np.array(X, dtype=np.float32)

def rule_ids(frames):
    """Rule/signature baseline: unknown ID, or per-ID rate > 1.5x nominal."""
    known = dict(zip(ids.tolist(), periods)); last = {}; out = []
    for t, i, p, y, a in frames:
        if i not in known: out.append(1)
        else: out.append(int((t - last.get(i, -1)) < 0.5 * known[i]))
        last[i] = t
    return np.array(out)

T = 20.0
train = inject(inject(normal_traffic(T), T, 1), T, 2)          # train sees DoS + fuzzing only
clean = normal_traffic(T)
tests = {name: inject(normal_traffic(T), T, k) for k, name in [(1, "DoS"), (2, "Fuzzing"), (3, "Spoofing"), (4, "Replay"), (5, "Masquerade")]}

Xtr = features(train); ytr = np.array([f[3] for f in train])
sc = StandardScaler().fit(Xtr)
clf = MLPClassifier(hidden_layer_sizes=(32, 16), max_iter=60, random_state=0).fit(sc.transform(Xtr), ytr)

Xn = features(clean); scn = StandardScaler().fit(Xn)
ae = MLPRegressor(hidden_layer_sizes=(16, 6, 16), max_iter=80, random_state=0).fit(scn.transform(Xn), scn.transform(Xn))
err_n = ((ae.predict(scn.transform(Xn)) - scn.transform(Xn)) ** 2).mean(1)
thr = np.quantile(err_n, 0.999)

res = {}
for name, fr in tests.items():
    X = features(fr); y = np.array([f[3] for f in fr])
    r = {}
    r["Rule-based"] = rule_ids(fr)
    r["Supervised MLP"] = clf.predict(sc.transform(X))
    e = ((ae.predict(scn.transform(X)) - scn.transform(X)) ** 2).mean(1); r["One-class AE"] = (e > thr).astype(int)
    # per-ID k-of-n alarm filter: raise alarm only if >=2 of the last 3 frames of that ID exceed threshold
    hist = {}; filt = []; known_set = set(ids.tolist())
    for (t_, i_, *_), flag in zip(fr, r["One-class AE"]):
        if i_ not in known_set: filt.append(int(flag)); continue
        h = hist.setdefault(i_, []); h.append(int(flag)); h[:] = h[-3:]; filt.append(int(sum(h) >= 2))
    r["AE + 2-of-3 filter"] = np.array(filt)
    r["Hybrid (proposed)"] = np.maximum(r["Rule-based"], r["AE + 2-of-3 filter"])
    res[name] = {}
    for m, pred in r.items():
        p, rc, f1, _ = precision_recall_fscore_support(y, pred, average="binary", zero_division=0)
        fpr = float(((pred == 1) & (y == 0)).sum() / max((y == 0).sum(), 1))
        res[name][m] = dict(precision=round(p, 3), recall=round(rc, 3), f1=round(f1, 3), fpr=round(fpr, 4))
    res[name]["_frames"] = int(len(y)); res[name]["_attack_frames"] = int(y.sum())

def params(m): return int(sum(w.size for w in m.coefs_) + sum(b.size for b in m.intercepts_))
x1 = sc.transform(Xtr[:1]); t0 = time.perf_counter()
for _ in range(2000): clf.predict(x1)
lat_mlp = (time.perf_counter() - t0) / 2000 * 1e6
xa = scn.transform(Xn[:1]); t0 = time.perf_counter()
for _ in range(2000): ae.predict(xa)
lat_ae = (time.perf_counter() - t0) / 2000 * 1e6
bus_load = len(clean) * FRAME_T / T
res["_model"] = dict(n_features=int(Xtr.shape[1]), mlp_params=params(clf), ae_params=params(ae),
                     mlp_int8_kB=round(params(clf) / 1024, 2), ae_int8_kB=round(params(ae) / 1024, 2),
                     mlp_latency_us_python=round(lat_mlp, 1), ae_latency_us_python=round(lat_ae, 1),
                     mlp_macs=int(sum(w.size for w in clf.coefs_)), ae_macs=int(sum(w.size for w in ae.coefs_)),
                     normal_bus_load=round(bus_load, 3), train_frames=int(len(ytr)), n_ids=N_IDS)
print(json.dumps(res, indent=1))
json.dump(res, open("/home/claude/sim/results.json", "w"), indent=1)

# where do the AE false alarms fall? share of false positives outside the attack window (+-0.2 s)
print("FP_outside_window")
for name, fr in tests.items():
    X = features(fr); y = np.array([f[3] for f in fr]); tt = np.array([f[0] for f in fr])
    e = ((ae.predict(scn.transform(X)) - scn.transform(X)) ** 2).mean(1); pred = (e > thr)
    fp = pred & (y == 0); out = fp & ((tt < T*0.3-0.2) | (tt > T*0.7+0.2))
    print(name, int(fp.sum()), int(out.sum()), "normal-region FPR=%.4f" % (out.sum() / max(((y==0)&((tt < T*0.3-0.2)|(tt > T*0.7+0.2))).sum(),1)))
