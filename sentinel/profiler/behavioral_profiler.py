"""
Behavioral Profiler - Analyzes attacker actions and maps to TTPs
"""
from typing import List, Dict
from sklearn.cluster import DBSCAN
import numpy as np
from datetime import datetime


class BehavioralProfiler:
    """Profile attacker behavior and map to MITRE ATT&CK TTPs"""
    
    # MITRE ATT&CK TTP mappings
    TTP_MAPPINGS = {
        "sql_injection": ["T1190"],  # Exploit Public-Facing Application
        "xss": ["T1190", "T1059.007"],  # Exploit + JavaScript
        "command_injection": ["T1059"],  # Command and Scripting Interpreter
        "path_traversal": ["T1083"],  # File and Directory Discovery
        "credential_access": ["T1110", "T1078"],  # Brute Force, Valid Accounts
        "enumeration": ["T1087", "T1083"],  # Account/File Discovery
        "data_exfiltration": ["T1567", "T1041"],  # Exfiltration
        "privilege_escalation": ["T1068", "T1078"],  # Exploit, Valid Accounts
        "persistence": ["T1505", "T1543"],  # Server Software Component
    }
    
    def __init__(self):
        pass
    
    def analyze_session(self, captures: List[Dict]) -> Dict:
        """
        Analyze a complete session to build attacker profile
        
        Args:
            captures: List of captured request dictionaries
            
        Returns:
            Attacker profile with TTPs, intent, sophistication
        """
        if not captures:
            return self._empty_profile()
        
        # Extract action sequence
        actions = [self._classify_action(c) for c in captures]
        
        # Map to TTPs
        ttps = self._extract_ttps(captures)
        
        # Classify intent
        intent = self._classify_intent(actions)
        
        # Score sophistication
        sophistication = self._score_sophistication(captures, actions)
        
        # Cluster similar sessions (requires multiple sessions)
        cluster_id = -1  # Placeholder
        
        profile = {
            "session_id": captures[0].get("session_id", "unknown"),
            "action_sequence": actions,
            "action_count": len(actions),
            "ttps": ttps,
            "intent": intent,
            "sophistication_score": sophistication,
            "cluster_id": cluster_id,
            "duration_seconds": self._calculate_duration(captures),
            "unique_endpoints": len(set(c.get("path", "") for c in captures)),
            "summary": self._generate_summary(actions, ttps, intent)
        }
        
        return profile
    
    def _classify_action(self, capture: Dict) -> str:
        """Classify a single request into an action type"""
        path = capture.get("path", "")
        method = capture.get("method", "GET")
        payloads = capture.get("payloads", [])
        
        # Check for attack payloads
        if payloads:
            payload_types = [p.get("type", "") for p in payloads]
            if "sql_injection" in payload_types:
                return "sql_injection_attempt"
            if "xss" in payload_types:
                return "xss_attempt"
            if "command_injection" in payload_types:
                return "command_injection_attempt"
            if "path_traversal" in payload_types:
                return "path_traversal_attempt"
        
        # Check for enumeration patterns
        if "/users" in path or "/api/v1/users" in path:
            return "user_enumeration"
        if "/admin" in path:
            return "admin_access_attempt"
        if "/config" in path or "/.env" in path:
            return "config_disclosure_attempt"
        if "/login" in path:
            return "authentication_attempt"
        if "/upload" in path and method == "POST":
            return "file_upload_attempt"
        if "/documents" in path and "download" in path:
            return "data_access_attempt"
        
        # Default classification
        if method == "GET":
            return "reconnaissance"
        elif method == "POST":
            return "exploitation_attempt"
        elif method in ["PUT", "PATCH"]:
            return "modification_attempt"
        elif method == "DELETE":
            return "deletion_attempt"
        
        return "unknown_action"
    
    def _extract_ttps(self, captures: List[Dict]) -> List[str]:
        """Extract MITRE ATT&CK TTPs from captures"""
        ttps = set()
        
        for capture in captures:
            payloads = capture.get("payloads", [])
            
            for payload in payloads:
                payload_type = payload.get("type", "")
                if payload_type in self.TTP_MAPPINGS:
                    ttps.update(self.TTP_MAPPINGS[payload_type])
            
            # Check for specific behaviors
            path = capture.get("path", "")
            
            if "/admin" in path or "/config" in path:
                ttps.add("T1083")  # File Discovery
            
            if "/login" in path:
                ttps.add("T1110")  # Brute Force
            
            if "/upload" in path:
                ttps.add("T1105")  # Ingress Tool Transfer
        
        return sorted(list(ttps))
    
    def _classify_intent(self, actions: List[str]) -> str:
        """Classify attacker's primary intent"""
        action_counts = {}
        for action in actions:
            action_counts[action] = action_counts.get(action, 0) + 1
        
        # Analyze action patterns
        total = len(actions)
        
        # Data exfiltration
        if action_counts.get("data_access_attempt", 0) / total > 0.3:
            return "data_exfiltration"
        
        # Exploitation
        exploit_actions = [
            "sql_injection_attempt",
            "xss_attempt",
            "command_injection_attempt"
        ]
        exploit_count = sum(action_counts.get(a, 0) for a in exploit_actions)
        if exploit_count / total > 0.4:
            return "exploitation"
        
        # Reconnaissance
        recon_actions = [
            "reconnaissance",
            "user_enumeration",
            "config_disclosure_attempt"
        ]
        recon_count = sum(action_counts.get(a, 0) for a in recon_actions)
        if recon_count / total > 0.5:
            return "reconnaissance"
        
        # Privilege escalation
        if action_counts.get("admin_access_attempt", 0) > 0:
            return "privilege_escalation"
        
        # Default
        return "unknown_intent"
    
    def _score_sophistication(self, captures: List[Dict], actions: List[str]) -> float:
        """
        Score attacker sophistication (0-10)
        
        Factors:
        - Variety of attack types
        - Use of obfuscation/encoding
        - Targeted vs spray-and-pray
        - Tool signatures
        """
        score = 0.0
        
        # Variety of attacks (0-3 points)
        unique_attacks = len(set(a for a in actions if "attempt" in a))
        score += min(3.0, unique_attacks * 0.5)
        
        # Obfuscation detection (0-2 points)
        for capture in captures:
            combined = f"{capture.get('url', '')} {capture.get('body', '')}"
            if "base64" in combined.lower() or "%25" in combined:  # Double encoding
                score += 2.0
                break
        
        # Tool signatures (0-2 points)
        user_agents = [c.get("headers", {}).get("User-Agent", "") for c in captures]
        if any("sqlmap" in ua.lower() or "nikto" in ua.lower() for ua in user_agents):
            score += 1.0  # Automated tool = less sophisticated
        else:
            score += 2.0  # Manual/custom tool = more sophisticated
        
        # Targeted behavior (0-3 points)
        if len(captures) < 10:
            # Few targeted requests
            score += 3.0
        elif len(captures) > 50:
            # Spray-and-pray
            score += 1.0
        else:
            score += 2.0
        
        return min(10.0, score)
    
    def _calculate_duration(self, captures: List[Dict]) -> float:
        """Calculate session duration in seconds"""
        if len(captures) < 2:
            return 0.0
        
        try:
            timestamps = [
                datetime.fromisoformat(c.get("timestamp", ""))
                for c in captures
                if c.get("timestamp")
            ]
            
            if len(timestamps) < 2:
                return 0.0
            
            duration = (max(timestamps) - min(timestamps)).total_seconds()
            return duration
        except:
            return 0.0
    
    def _generate_summary(self, actions: List[str], ttps: List[str], intent: str) -> str:
        """Generate human-readable summary"""
        action_summary = ", ".join(set(actions[:5]))  # First 5 unique actions
        ttp_summary = ", ".join(ttps[:3]) if ttps else "None"
        
        summary = (
            f"Intent: {intent.replace('_', ' ').title()}. "
            f"Actions: {action_summary}. "
            f"TTPs: {ttp_summary}. "
            f"Total requests: {len(actions)}."
        )
        
        return summary
    
    def _empty_profile(self) -> Dict:
        """Return empty profile"""
        return {
            "session_id": "unknown",
            "action_sequence": [],
            "action_count": 0,
            "ttps": [],
            "intent": "unknown",
            "sophistication_score": 0.0,
            "cluster_id": -1,
            "duration_seconds": 0.0,
            "unique_endpoints": 0,
            "summary": "No data available"
        }
    
    def cluster_sessions(self, profiles: List[Dict]) -> List[Dict]:
        """
        Cluster similar attacker sessions using DBSCAN
        
        Args:
            profiles: List of attacker profiles
            
        Returns:
            Updated profiles with cluster_id assigned
        """
        if len(profiles) < 3:
            # Need at least 3 for meaningful clustering
            return profiles
        
        # Create feature vectors from profiles
        features = []
        for profile in profiles:
            feature_vector = [
                profile["action_count"],
                profile["sophistication_score"],
                profile["duration_seconds"],
                profile["unique_endpoints"],
                len(profile["ttps"])
            ]
            features.append(feature_vector)
        
        X = np.array(features)
        
        # Normalize features
        X_normalized = (X - X.mean(axis=0)) / (X.std(axis=0) + 1e-8)
        
        # Cluster with DBSCAN
        clustering = DBSCAN(eps=0.5, min_samples=2).fit(X_normalized)
        
        # Assign cluster IDs
        for i, profile in enumerate(profiles):
            profile["cluster_id"] = int(clustering.labels_[i])
        
        return profiles
