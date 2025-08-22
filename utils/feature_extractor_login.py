import math



import requests

ABUSEIPDB_API_KEY = "your-abuseipdb-key"  # Optional if using public
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError

def ip_to_asn(ip):
    """
    Returns ASN info from a given IP address using WHOIS lookup.
    Returns a dictionary with ASN number, organization, and country.
    """
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap(depth=1)
        return {
            "asn": res.get("asn", None),
            "asn_description": res.get("asn_description", None),
            "asn_country_code": res.get("asn_country_code", None),
            "network_name": res.get("network", {}).get("name", None)
        }
    except IPDefinedError:
        return {"asn": "Reserved", "asn_description": "Private/Reserved", "asn_country_code": None}
    except Exception as e:
        print(f"WHOIS lookup failed for IP {ip}: {e}")
        return {"asn": None, "asn_description": None, "asn_country_code": None}


def enrich_ip_osint(ip):
    risk_flags = {
        "ip_blacklisted_flag": False,
        "asn_risky": False,
        "vpn_detected_flag": False
    }

    # Example OSINT - Public AbuseIPDB check (if allowed)
    try:
        response = requests.get(
            f"https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 30},
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        )
        data = response.json()["data"]
        if data["abuseConfidenceScore"] >= 50:
            risk_flags["ip_blacklisted_flag"] = True
        if "VPN" in data.get("usageType", ""):
            risk_flags["vpn_detected_flag"] = True
    except:
        pass  # fallback or offline

    # Example ASN risky list (local or remote)
    risky_asns = {"AS12389", "AS9009", "AS8075"}  # add more
    risk_flags["asn_risky"] = ip_to_asn(ip) in risky_asns

    return risk_flags


def extract_features_from_login(login_event):
    """
    Full feature extractor for BAIDS registration/login event.
    Assumes login_event contains all current + historical data.
    """

    # Device & SIM Fingerprint
    imei_change_flag = int(login_event.get("imei") != login_event.get("prev_imei"))
    imsi_change_flag = int(login_event.get("imsi") != login_event.get("prev_imsi"))
    android_id_mismatch = int(login_event.get("android_id") != login_event.get("prev_android_id"))
    device_model_mismatch = int(login_event.get("device_model") != login_event.get("prev_device_model"))
    sim_slot_change_detected = int(login_event.get("sim_slot") != login_event.get("prev_sim_slot"))

    device_model = str(login_event.get("device_model", "")).lower()
    is_rooted = bool(login_event.get("is_rooted", False))
    is_emulator = int("emulator" in device_model or is_rooted)

    # Network & IP Intelligence
    ip_asn_mismatch = int(login_event.get("ip_asn") != login_event.get("prev_ip_asn"))
    risky_asns = set(login_event.get("risky_asns", []))
    asn_risky = int(login_event.get("ip_asn") in risky_asns)
    ip_country_mismatch = int(login_event.get("ip_country") != login_event.get("sim_country"))

    ip_address = login_event.get("ip_address")
    ip_blacklist = set(login_event.get("ip_blacklist", []))
    ip_blacklisted_flag = int(ip_address in ip_blacklist)

    geo_ip_distance_km = login_event.get("geo_ip_distance_km", 0.0)
    vpn_detected_flag = int(login_event.get("vpn_detected", False))
    carrier_mismatch = int(login_event.get("sim_carrier") != login_event.get("ip_carrier"))

    # Geolocation & Behavioral Drift
    gps_jump_distance_km = login_event.get("gps_jump_distance_km", 0.0)
    login_time_local_hour = login_event.get("login_time_local_hour", 12)
    odd_hour_flag = int(login_time_local_hour in [0, 1, 2, 3, 4])

    weekday_vs_weekend = int(login_event.get("is_weekend") != login_event.get("prev_is_weekend"))
    location_cluster_id = login_event.get("location_cluster_id", -1)
    known_clusters = set(login_event.get("known_location_clusters", []))
    location_cluster_drift_flag = int(location_cluster_id not in known_clusters)

    # Session / Latency / App Behavior
    login_latency_ms = login_event.get("login_latency_ms", 0)
    latency_score = min(math.ceil(login_latency_ms / 250), 5)
    session_token_reused = int(login_event.get("session_token") in login_event.get("previous_tokens", []))
    multiple_login_attempts = int(login_event.get("multiple_login_attempts", 0))
    session_device_consistency = int(login_event.get("device_id") in login_event.get("trusted_device_ids", []))
    app_version_mismatch = int(login_event.get("app_version") != login_event.get("expected_app_version"))

    # User Account History
    login_count_past_7_days = login_event.get("login_count_past_7_days", 0)
    anomalous_login_ratio = login_event.get("anomalous_login_ratio", 0.0)
    known_devices_count = len(login_event.get("known_device_ids", []))
    unknown_device_flag = int(login_event.get("device_id") not in login_event.get("known_device_ids", []))

    # Features dict (same keys, now safe defaults)
    features = {
        "imei_change_flag": imei_change_flag,
        "imsi_change_flag": imsi_change_flag,
        "android_id_mismatch": android_id_mismatch,
        "device_model_mismatch": device_model_mismatch,
        "sim_slot_change_detected": sim_slot_change_detected,
        "is_emulator": is_emulator,
        "ip_asn_mismatch": ip_asn_mismatch,
        "asn_risky": asn_risky,
        "ip_country_mismatch": ip_country_mismatch,
        "ip_blacklisted_flag": ip_blacklisted_flag,
        "geo_ip_distance_km": geo_ip_distance_km,
        "vpn_detected_flag": vpn_detected_flag,
        "carrier_mismatch": carrier_mismatch,
        "gps_jump_distance_km": gps_jump_distance_km,
        "login_time_local_hour": login_time_local_hour,
        "odd_hour_flag": odd_hour_flag,
        "weekday_vs_weekend": weekday_vs_weekend,
        "location_cluster_id": location_cluster_id,
        "location_cluster_drift_flag": location_cluster_drift_flag,
        "login_latency_ms": login_latency_ms,
        "latency_score": latency_score,
        "session_token_reused": session_token_reused,
        "multiple_login_attempts": multiple_login_attempts,
        "session_device_consistency": session_device_consistency,
        "app_version_mismatch": app_version_mismatch,
        "login_count_past_7_days": login_count_past_7_days,
        "anomalous_login_ratio": anomalous_login_ratio,
        "known_devices_count": known_devices_count,
        "unknown_device_flag": unknown_device_flag,
    }

    return features
