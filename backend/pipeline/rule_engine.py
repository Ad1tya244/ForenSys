"""
ForenSys Modular Rule Engine
Automatically discovers and executes all BaseRule subclasses dynamically located in pipeline/rules/
"""

import importlib
import inspect
import os
import pkgutil
from typing import Dict, Any, List, Type, Optional
from pipeline.rules.base import BaseRule, DetectionAlert
from pipeline.state_engine import BehaviorStateEngine

class RuleEngine:
    def __init__(self, rules_dir: Optional[str] = None) -> None:
        self.rules_dir = rules_dir if rules_dir else os.path.join(os.path.dirname(__file__), "rules")
        self.rules: List[BaseRule] = []
        self.discover_rules()

    def discover_rules(self) -> List[BaseRule]:
        """Automatically scans pipeline/rules/ directory and instantiates all BaseRule subclasses."""
        self.rules.clear()
        package_name = "pipeline.rules"

        # Walk through all python files in rules directory
        for _, module_name, is_pkg in pkgutil.iter_modules([self.rules_dir]):
            if module_name == "base" or is_pkg:
                continue
            
            full_module_name = f"{package_name}.{module_name}"
            try:
                module = importlib.import_module(full_module_name)
                # Re-import if module was modified dynamically
                importlib.reload(module)
                
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if issubclass(obj, BaseRule) and obj is not BaseRule:
                        rule_instance = obj()
                        self.rules.append(rule_instance)
            except Exception as e:
                print(f"[RuleEngine] Error loading rule module '{module_name}': {e}")

        return self.rules

    def evaluate_all(self, state_engine: BehaviorStateEngine, config: Dict[str, Any], now: Optional[float] = None) -> List[DetectionAlert]:
        """Runs all discovered rules against the behavior state engine and returns generated alerts."""
        alerts: List[DetectionAlert] = []
        for rule in self.rules:
            try:
                rule_alerts = rule.evaluate(state_engine, config, now)
                alerts.extend(rule_alerts)
            except Exception as e:
                print(f"[RuleEngine] Error executing rule '{rule.name}': {e}")
        return alerts

    def get_rule_catalog(self, config: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Returns metadata and current thresholds for all loaded rules."""
        cfg = config if config is not None else {}
        catalog = []
        for i, r in enumerate(self.rules, 1):
            rule_id = f"RULE-0{i}" if i < 10 else f"RULE-{i}"
            name_lower = r.name.lower()
            
            threshold = 20
            window_sec = 10.0
            
            if "icmp" in name_lower or rule_id == "RULE-01":
                threshold = cfg.get("icmp_threshold", 20)
                window_sec = cfg.get("icmp_window_sec", 10.0)
            elif "port scan" in name_lower or "scan" in name_lower or rule_id == "RULE-02":
                threshold = cfg.get("portscan_threshold", 20)
                window_sec = cfg.get("portscan_window_sec", 15.0)
            elif "syn" in name_lower or rule_id == "RULE-03":
                threshold = cfg.get("syn_threshold", 50)
                window_sec = cfg.get("syn_window_sec", 10.0)
            elif "brute force" in name_lower or "auth" in name_lower or rule_id == "RULE-04":
                threshold = cfg.get("auth_failure_limit", 3)
                window_sec = cfg.get("auth_window_sec", 60.0)
            elif "dns" in name_lower or rule_id == "RULE-05":
                threshold = cfg.get("dns_beacon_min_queries", 5)
                window_sec = cfg.get("dns_beacon_window_sec", 60.0)
            elif "exfiltration" in name_lower or rule_id == "RULE-06":
                threshold = cfg.get("data_exfiltration_bytes", 52428800)
                window_sec = cfg.get("data_exfiltration_window_sec", 30.0)
                
            catalog.append({
                "id": rule_id,
                "name": r.name,
                "description": r.description,
                "datasource": r.datasource,
                "time_window": f"{int(window_sec)}s",
                "threshold": threshold,
                "severity": r.severity,
                "mitre_tactics": r.mitre_tactics,
                "confidence": r.confidence,
                "recommended_remediation": r.recommended_remediation,
            })
        return catalog
