# ================================================
# hybrid_predictor.py – Patch (drop-in replacement)
# ================================================
# Add this patch in your hybrid_predictor.py to fix numeric vector usage,
# add stable AE thresholding, and return human-readable explanations.


import numpy as np
from utils.feature_extractor_login import extract_features_from_login
from utils.rules import compute_rule_risk_score
import json
import joblib
from keras.models import load_model

with open("profiles/risk_profiles.json") as f:
    PROFILES = json.load(f)

if_model = joblib.load("saved_models/isolation_forest_model.pkl")
scaler = joblib.load("saved_models/standard_scaler.pkl")

ae_model = load_model("saved_models/autoencoder_model.h5", compile=False)


def _build_numeric_vector(features: dict):
    numeric = []
    ordered_keys = []
    for k, v in features.items():
        ordered_keys.append(k)
        if isinstance(v, bool):
            numeric.append(1.0 if v else 0.0)
        elif isinstance(v, (int, float)):
            numeric.append(float(v))
        elif v is None:
            numeric.append(0.0)
        else:
            # non-numeric -> 0, but keep position aligned
            numeric.append(0.0)
    return np.array([numeric], dtype=np.float32), ordered_keys


def _build_explanations(fx: dict, rule_score: float, if_scr: float, ae_loss: float):
    msgs = []
    # heuristic, adapt to your actual feature names
    if fx.get("geo_mismatch"):
        msgs.append("GeoIP country does not match SIM/MCC region")
    if fx.get("device_mismatch") or fx.get("device_imei_mismatch"):
        msgs.append("Device/IMEI mismatch from previous known history")
    if fx.get("new_device"):
        msgs.append("First-time login from a new device")
    if fx.get("vpn_detected") or fx.get("vpn"):
        msgs.append("VPN/Proxy usage detected during registration")
    if fx.get("odd_hour") or (isinstance(fx.get("hour"), (int, float)) and (fx["hour"] < 6 or fx["hour"] > 23)):
        msgs.append("Unusual login hour compared to user baseline")
    if isinstance(fx.get("ip_risk_score"), (int, float)) and fx["ip_risk_score"] > 70:
        msgs.append("High IP reputation risk score")
    # model-based
    if if_scr > 0.5:
        msgs.append("Isolation Forest flagged this vector as anomalous")
    if ae_loss > 0.02:
        msgs.append("Autoencoder reconstruction error above threshold")
    if rule_score > 50:
        msgs.append("Rule engine high risk (weighted)")
    if not msgs:
        msgs.append("No single red-flag, but combined risk above profile threshold")
    return msgs


def hybrid_predict(login_event, profile_name="Default"):
    features = extract_features_from_login(login_event)
    profile = PROFILES.get(profile_name, PROFILES["Default"])

    # Vector for ML models (fixed)
    feature_vector, ordered_keys = _build_numeric_vector(features)
    feature_vector = scaler.transform(feature_vector)

    # Isolation Forest (positive -> more anomalous)
    if_raw = if_model.decision_function(feature_vector)[0]
    if_score = float(-1.0 * if_raw)

    # Autoencoder reconstruction error
    ae_pred = ae_model.predict(feature_vector, verbose=0)[0]
    ae_loss = float(np.mean(np.square(feature_vector - ae_pred)))

    # Thresholds – make explicit from profile
    ae_threshold = float(profile.get("ae_threshold", 0.02))
    hybrid_threshold = float(profile.get("hybrid_threshold", 50.0))

    ae_flag = ae_loss > ae_threshold
    if_flag = if_score > profile.get("if_threshold", 0.5)

    # Rule-based
    # Support both numeric score return or (score, reasons)
    rule_out = compute_rule_risk_score(features)
    rule_score = rule_out[0] if isinstance(rule_out, (list, tuple)) else rule_out
    rule_reasons = rule_out[1] if isinstance(rule_out, (list, tuple)) and len(rule_out) > 1 else []

    # Weighted decision – assume rule_score is on 0-100 scale, IF/AE scaled to 0-100
    if_scaled = min(100.0, max(0.0, if_score * 100.0))
    ae_scaled = min(100.0, max(0.0, (ae_loss / max(1e-6, ae_threshold)) * 50.0))

    non_rule = max(if_scaled, ae_scaled)
    final_score = (1 - profile.get("rule_weight", 0.4)) * non_rule + profile.get("rule_weight", 0.4) * float(rule_score)

    verdict = "⚠️ Suspicious" if final_score > hybrid_threshold else "✅ Legit"

    explanations = rule_reasons or _build_explanations(features, rule_score, if_score, ae_loss)

    return {
        "verdict": verdict,
        "final_risk_score": round(float(final_score), 2),
        "rule_score": round(float(rule_score), 2),
        "ae_loss": round(float(ae_loss), 5),
        "if_score": round(float(if_score), 5),
        "flags": {"ae_flag": bool(ae_flag), "if_flag": bool(if_flag), "rule_flag": float(rule_score) > hybrid_threshold},
        "profile_used": profile_name,
        "explanations": explanations,
        "feature_keys": ordered_keys,
    }


