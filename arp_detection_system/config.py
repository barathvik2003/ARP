import os
import yaml
from dataclasses import dataclass, field
from typing import List, Optional


DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.yaml")


@dataclass
class ServerConfig:
    name: str
    host: str
    os_type: str  # "linux" or "windows"
    port: int = 22
    username: str = ""
    password: str = ""
    ssh_key_path: str = ""
    winrm_port: int = 5985
    winrm_use_ssl: bool = False


@dataclass
class DetectionConfig:
    arp_table_poll_interval: int = 5
    gateway_ip: str = ""
    alert_threshold: int = 3
    mac_change_sensitivity: int = 1
    duplicate_ip_detection: bool = True
    gratuitous_arp_detection: bool = True
    rate_limit_detection: bool = True
    max_arp_rate_per_second: int = 50


@dataclass
class RemediationConfig:
    auto_block: bool = False
    auto_isolate: bool = False
    block_duration_seconds: int = 300
    notify_only: bool = True
    max_block_time: int = 3600


@dataclass
class Config:
    servers: List[ServerConfig] = field(default_factory=list)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    remediation: RemediationConfig = field(default_factory=RemediationConfig)
    log_level: str = "INFO"
    log_retention_days: int = 30
    report_interval: int = 3600


def load_config(path: Optional[str] = None) -> Config:
    if path is None:
        path = DEFAULT_CONFIG_PATH

    config = Config()

    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        if "servers" in data:
            for s in data["servers"]:
                config.servers.append(ServerConfig(**s))

        if "detection" in data:
            d = data["detection"]
            config.detection = DetectionConfig(
                arp_table_poll_interval=d.get("arp_table_poll_interval", 5),
                gateway_ip=d.get("gateway_ip", ""),
                alert_threshold=d.get("alert_threshold", 3),
                mac_change_sensitivity=d.get("mac_change_sensitivity", 1),
                duplicate_ip_detection=d.get("duplicate_ip_detection", True),
                gratuitous_arp_detection=d.get("gratuitous_arp_detection", True),
                rate_limit_detection=d.get("rate_limit_detection", True),
                max_arp_rate_per_second=d.get("max_arp_rate_per_second", 50),
            )

        if "remediation" in data:
            r = data["remediation"]
            config.remediation = RemediationConfig(
                auto_block=r.get("auto_block", False),
                auto_isolate=r.get("auto_isolate", False),
                block_duration_seconds=r.get("block_duration_seconds", 300),
                notify_only=r.get("notify_only", True),
                max_block_time=r.get("max_block_time", 3600),
            )

        config.log_level = data.get("log_level", "INFO")
        config.log_retention_days = data.get("log_retention_days", 30)
        config.report_interval = data.get("report_interval", 3600)

    return config


def save_config(config: Config, path: Optional[str] = None):
    if path is None:
        path = DEFAULT_CONFIG_PATH

    data = {
        "servers": [
            {
                "name": s.name,
                "host": s.host,
                "os_type": s.os_type,
                "port": s.port,
                "username": s.username,
                "password": s.password,
                "ssh_key_path": s.ssh_key_path,
                "winrm_port": s.winrm_port,
                "winrm_use_ssl": s.winrm_use_ssl,
            }
            for s in config.servers
        ],
        "detection": {
            "arp_table_poll_interval": config.detection.arp_table_poll_interval,
            "gateway_ip": config.detection.gateway_ip,
            "alert_threshold": config.detection.alert_threshold,
            "mac_change_sensitivity": config.detection.mac_change_sensitivity,
            "duplicate_ip_detection": config.detection.duplicate_ip_detection,
            "gratuitous_arp_detection": config.detection.gratuitous_arp_detection,
            "rate_limit_detection": config.detection.rate_limit_detection,
            "max_arp_rate_per_second": config.detection.max_arp_rate_per_second,
        },
        "remediation": {
            "auto_block": config.remediation.auto_block,
            "auto_isolate": config.remediation.auto_isolate,
            "block_duration_seconds": config.remediation.block_duration_seconds,
            "notify_only": config.remediation.notify_only,
            "max_block_time": config.remediation.max_block_time,
        },
        "log_level": config.log_level,
        "log_retention_days": config.log_retention_days,
        "report_interval": config.report_interval,
    }

    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, default_flow_style=False)
