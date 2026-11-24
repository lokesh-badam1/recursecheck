import yaml


def load(path):
    with open(path) as f:
        cfg = yaml.safe_load(f)
    cfg.setdefault("marker_ip", "192.0.2.123")
    cfg.setdefault("lab_net", "10.10.0.0/16")
    cfg.setdefault("web_ip", "10.10.2.20")            # web UI, external vantage
    cfg.setdefault("web_internal_ip", "10.10.1.20")   # web UI alias inside the allowed range, internal vantage
    return cfg
