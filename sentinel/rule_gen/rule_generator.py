"""
Rule Generator - Synthesizes WAF rules from simulation results
"""
import re
from typing import Dict, Optional
from datetime import datetime
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
from shared.events.schemas import WAFRule, RuleMatch, RuleEvidence


class RuleGenerator:
    """Generate WAF rules from attack payloads and simulation results"""
    
    def __init__(self):
        pass
    
    def generate_rule(
        self,
        payload: Dict,
        sim_result: Dict,
        profile: Optional[Dict] = None
    ) -> Optional[WAFRule]:
        """
        Generate a WAF rule from simulation result
        
        Args:
            payload: Payload dict with type, value, location
            sim_result: Simulation result with verdict, severity
            profile: Optional attacker profile for context
            
        Returns:
            WAFRule object or None if not applicable
        """
        # Only generate rules for confirmed exploits
        if sim_result.get("verdict") != "exploit_possible":
            print(f"[RULE_GEN] Skipping rule: verdict={sim_result.get('verdict')}")
            return None
        
        payload_type = payload.get("type", "unknown")
        payload_value = payload.get("value", "")
        severity = sim_result.get("severity", 5.0)
        
        print(f"[RULE_GEN] Generating rule for {payload_type} payload")
        
        # Generate pattern based on payload type
        if payload_type == "sql_injection":
            pattern, rule_type = self._generate_sql_pattern(payload_value)
        
        elif payload_type == "xss":
            pattern, rule_type = self._generate_xss_pattern(payload_value)
        
        elif payload_type == "command_injection":
            pattern, rule_type = self._generate_command_pattern(payload_value)
        
        elif payload_type == "path_traversal":
            pattern, rule_type = self._generate_path_traversal_pattern(payload_value)
        
        else:
            # Generic string match
            pattern = re.escape(payload_value)
            rule_type = "string"
        
        # Calculate confidence
        confidence = self._calculate_confidence(sim_result, profile, payload)
        
        # Determine action
        action = self._determine_action(severity, confidence)
        
        # Assign priority
        priority = self._assign_priority(severity, confidence)
        
        # Create rule
        rule = WAFRule(
            priority=priority,
            match=RuleMatch(
                type=rule_type,
                pattern=pattern,
                location=self._determine_locations(payload_type),
                flags={"caseless": True} if rule_type == "regex" else {}
            ),
            action=action,
            confidence=confidence,
            evidence=RuleEvidence(
                simulation_id=sim_result.get("simulation_id", "unknown"),
                sample_payloads=[payload_value],
                severity=severity,
                attack_type=payload_type
            ),
            audit={
                "sim_verdict": sim_result.get("verdict"),
                "sim_score": severity,
                "attacker_ttp": profile.get("ttps", []) if profile else []
            }
        )
        
        print(f"[RULE_GEN] Generated rule: {rule.rule_id} (confidence={confidence:.2f}, action={action})")
        
        return rule
    
    def _generate_sql_pattern(self, payload: str) -> tuple[str, str]:
        """Generate regex pattern for SQL injection"""
        # Generalize the pattern to catch variations
        
        # Common SQLi patterns
        if "OR" in payload.upper() and "=" in payload:
            # OR-based injection: ' OR '1'='1
            pattern = r"'\s*(OR|AND)\s*'[^']*'\s*=\s*'[^']*"
        
        elif "UNION" in payload.upper():
            # UNION-based injection
            pattern = r"UNION\s+(ALL\s+)?SELECT"
        
        elif "--" in payload or "/*" in payload:
            # Comment-based injection
            pattern = r"(--|#|/\*)"
        
        elif ";" in payload and any(kw in payload.upper() for kw in ["DROP", "DELETE", "INSERT"]):
            # Stacked queries
            pattern = r";\s*(DROP|DELETE|INSERT|UPDATE|CREATE)\s+"
        
        else:
            # Generic SQL keywords
            pattern = r"(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC)\s+"
        
        return pattern, "regex"
    
    def _generate_xss_pattern(self, payload: str) -> tuple[str, str]:
        """Generate regex pattern for XSS"""
        payload_lower = payload.lower()
        
        if "<script" in payload_lower:
            pattern = r"<script[^>]*>"
        
        elif "javascript:" in payload_lower:
            pattern = r"javascript:\s*"
        
        elif re.search(r"on\w+\s*=", payload_lower):
            # Event handlers: onerror=, onload=, etc.
            pattern = r"on\w+\s*=\s*['\"]?[^'\"]*['\"]?"
        
        elif "<iframe" in payload_lower:
            pattern = r"<iframe[^>]*>"
        
        else:
            # Generic XSS
            pattern = r"(<script|javascript:|on\w+\s*=|<iframe)"
        
        return pattern, "regex"
    
    def _generate_command_pattern(self, payload: str) -> tuple[str, str]:
        """Generate regex pattern for command injection"""
        # Check for command separators
        if any(sep in payload for sep in [";", "&&", "||", "|"]):
            pattern = r"[;&|]{1,2}\s*(cat|ls|whoami|wget|curl|bash|sh|nc|id|pwd)\s+"
        
        # Check for command substitution
        elif "$(" in payload or "`" in payload:
            pattern = r"(\$\(.*?\)|`.*?`)"
        
        else:
            # Generic shell commands
            pattern = r"(cat|ls|whoami|wget|curl|bash|sh|nc|netcat|python|perl|ruby)\s+"
        
        return pattern, "regex"
    
    def _generate_path_traversal_pattern(self, payload: str) -> tuple[str, str]:
        """Generate regex pattern for path traversal"""
        # Detect directory traversal patterns
        if "../" in payload or "..\\" in payload:
            pattern = r"(\.\.\/|\.\.\\){2,}"
        
        # Encoded traversal
        elif "%2e%2e" in payload.lower() or "%252e" in payload.lower():
            pattern = r"(%2e%2e|%252e){2,}"
        
        else:
            # Generic
            pattern = r"(\.\.\/|\.\.\\|%2e%2e){2,}"
        
        return pattern, "regex"
    
    def _calculate_confidence(
        self,
        sim_result: Dict,
        profile: Optional[Dict],
        payload: Dict
    ) -> float:
        """
        Calculate confidence score (0-1) for the rule
        
        Factors:
        - Simulation severity
        - Payload confidence
        - Attacker sophistication
        - Pattern quality
        """
        confidence = 0.0
        
        # Simulation severity (0-0.4)
        severity = sim_result.get("severity", 0.0)
        confidence += (severity / 10.0) * 0.4
        
        # Payload extraction confidence (0-0.3)
        payload_confidence = payload.get("confidence", 0.5)
        confidence += payload_confidence * 0.3
        
        # Attacker sophistication (0-0.2)
        if profile:
            sophistication = profile.get("sophistication_score", 5.0)
            confidence += (sophistication / 10.0) * 0.2
        else:
            confidence += 0.1  # Default
        
        # Pattern quality (0-0.1)
        # Higher confidence for well-defined patterns
        pattern_quality = 0.8  # Assume good patterns for now
        confidence += pattern_quality * 0.1
        
        return min(1.0, confidence)
    
    def _determine_action(self, severity: float, confidence: float) -> str:
        """Determine rule action based on severity and confidence"""
        if severity >= 9.0 and confidence >= 0.85:
            return "block"
        elif severity >= 7.0 and confidence >= 0.75:
            return "block"
        elif severity >= 5.0 and confidence >= 0.70:
            return "challenge"  # Rate limit or CAPTCHA
        else:
            return "tag"  # Just tag for monitoring
    
    def _assign_priority(self, severity: float, confidence: float) -> int:
        """
        Assign rule priority (higher = evaluated first)
        
        Range: 50-150
        """
        # Base priority from severity
        base_priority = int(severity * 10)  # 0-100
        
        # Adjust by confidence
        confidence_bonus = int(confidence * 30)  # 0-30
        
        priority = base_priority + confidence_bonus + 50  # 50-180
        
        return max(50, min(150, priority))
    
    def _determine_locations(self, payload_type: str) -> list[str]:
        """Determine where to apply the rule"""
        if payload_type == "sql_injection":
            return ["args", "body", "json_values"]
        
        elif payload_type == "xss":
            return ["args", "body", "headers", "json_values"]
        
        elif payload_type == "command_injection":
            return ["args", "body"]
        
        elif payload_type == "path_traversal":
            return ["args", "uri"]
        
        else:
            return ["args", "body"]
    
    def optimize_rule(self, rule: WAFRule, similar_payloads: list[str]) -> WAFRule:
        """
        Optimize rule by generalizing pattern to cover similar payloads
        
        Args:
            rule: Original rule
            similar_payloads: List of similar attack payloads
            
        Returns:
            Optimized rule with broader pattern
        """
        if not similar_payloads or rule.match.type != "regex":
            return rule
        
        print(f"[RULE_GEN] Optimizing rule {rule.rule_id} with {len(similar_payloads)} similar payloads")
        
        # Find common patterns across payloads
        # This is a simplified version - production would use more sophisticated NLP
        
        # For now, just add alternative patterns
        original_pattern = rule.match.pattern
        
        # Combine patterns with OR
        additional_patterns = []
        for payload in similar_payloads[:5]:  # Max 5 alternatives
            if payload != rule.evidence.sample_payloads[0]:
                # Escape and add
                additional_patterns.append(re.escape(payload))
        
        if additional_patterns:
            combined_pattern = f"({original_pattern}|{'|'.join(additional_patterns)})"
            rule.match.pattern = combined_pattern
            rule.evidence.sample_payloads.extend(similar_payloads[:5])
        
        return rule
