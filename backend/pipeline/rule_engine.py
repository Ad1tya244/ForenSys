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

    def get_rule_catalog(self) -> List[Dict[str, Any]]:
        """Returns metadata for all loaded rules."""
        return [
            {
                "name": r.name,
                "description": r.description,
                "datasource": r.datasource,
                "time_window": r.time_window,
                "severity": r.severity,
                "mitre_tactics": r.mitre_tactics,
                "confidence": r.confidence,
                "recommended_remediation": r.recommended_remediation,
            }
            for r in self.rules
        ]
