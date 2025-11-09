"""
Stage 5-7: Explainability Module - SHAP/LIME integration for model interpretability
Provides human-readable explanations for ML predictions
"""
import json
import os
from typing import Dict, List, Tuple
import numpy as np
from datetime import datetime

# Try importing explainability libraries
try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    print("[WARNING] shap not installed. Install with: pip install shap")
    SHAP_AVAILABLE = False

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from shared.utils.logging import get_logger

logger = get_logger(__name__)


class ExplainabilityEngine:
    """
    Provides model explainability using SHAP (SHapley Additive exPlanations)
    
    For MVP: rule-based feature importance
    For production: integrate actual SHAP with trained models
    """
    
    # Feature importance weights (hand-tuned for MVP)
    FEATURE_WEIGHTS = {
        "contains_sql_keywords": 0.95,
        "contains_xss_patterns": 0.90,
        "contains_cmd_patterns": 0.92,
        "max_payload_entropy": 0.75,
        "error_rate": 0.70,
        "request_rate_per_min": 0.65,
        "special_char_ratio": 0.60,
        "ua_fingerprint_score": 0.55,
        "endpoint_diversity": 0.50,
        "n_payloads": 0.45,
        "max_path_depth": 0.40,
        "avg_inter_request_ms": 0.35,
        "method_diversity": 0.30,
        "has_poi_tag": 0.85,
        "prior_poi_count": 0.80
    }
    
    def __init__(self):
        logger.info("Explainability engine initialized")
    
    def explain_verdict(self, features: Dict, verdict: Dict) -> Dict:
        """
        Generate explanation for a verdict
        
        Args:
            features: Feature vector used in prediction
            verdict: Verdict dict with scores
            
        Returns:
            Explanation dict with SHAP-style feature importances
        """
        try:
            logger.info(f"Generating explanation for session: {verdict.get('session_id')}")
            
            # Calculate feature importances
            feature_importances = self._calculate_importances(features, verdict)
            
            # Generate SHAP-style summary
            shap_summary = self._generate_shap_summary(feature_importances)
            
            # Generate natural language explanation
            narrative = self._generate_narrative(feature_importances, verdict)
            
            # Identify contributing vs. contradicting features
            contributors, contradictors = self._split_features(feature_importances)
            
            explanation = {
                "session_id": verdict.get("session_id"),
                "verdict": verdict.get("verdict"),
                "final_score": verdict.get("final_score"),
                "feature_importances": feature_importances,
                "shap_summary": shap_summary,
                "top_contributors": contributors[:5],
                "top_contradictors": contradictors[:3],
                "narrative": narrative,
                "generated_at": datetime.utcnow().isoformat()
            }
            
            logger.info(f"Explanation generated: {len(feature_importances)} features analyzed")
            
            return explanation
        
        except Exception as e:
            logger.error(f"Error generating explanation: {e}", exc_info=True)
            return {"error": str(e)}
    
    def _calculate_importances(self, features: Dict, verdict: Dict) -> List[Dict]:
        """
        Calculate feature importances (SHAP values approximation)
        
        For MVP: use rule-based importance
        For production: compute actual SHAP values from model
        """
        importances = []
        final_score = verdict.get("final_score", 0.0)
        
        for feature_name, feature_value in features.items():
            if not isinstance(feature_value, (int, float)):
                continue
            
            # Get base weight for this feature
            base_weight = self.FEATURE_WEIGHTS.get(feature_name, 0.3)
            
            # Calculate contribution to final score
            # Positive contribution if feature is "active" or high
            if feature_name.startswith("contains_"):
                # Binary features
                contribution = base_weight * feature_value * final_score
            else:
                # Continuous features - normalize and weight
                normalized_value = self._normalize_value(feature_name, feature_value)
                contribution = base_weight * normalized_value * final_score
            
            importances.append({
                "feature": feature_name,
                "value": feature_value,
                "importance": contribution,
                "base_weight": base_weight
            })
        
        # Sort by absolute importance
        importances.sort(key=lambda x: abs(x["importance"]), reverse=True)
        
        return importances
    
    def _normalize_value(self, feature_name: str, value: float) -> float:
        """Normalize feature value to [0, 1] range"""
        # Define reasonable ranges for different feature types
        ranges = {
            "max_payload_entropy": (0, 8),
            "error_rate": (0, 1),
            "request_rate_per_min": (0, 200),
            "special_char_ratio": (0, 1),
            "ua_fingerprint_score": (0, 1),
            "endpoint_diversity": (0, 1),
            "n_payloads": (0, 50),
            "max_path_depth": (0, 20),
            "avg_inter_request_ms": (0, 10000),
            "n_requests": (0, 200)
        }
        
        if feature_name in ranges:
            min_val, max_val = ranges[feature_name]
            normalized = (value - min_val) / (max_val - min_val)
            return max(0, min(1, normalized))
        
        return 0.5  # Default for unknown features
    
    def _generate_shap_summary(self, feature_importances: List[Dict]) -> Dict:
        """
        Generate SHAP-style summary
        
        Returns top positive and negative contributors
        """
        positive = [f for f in feature_importances if f["importance"] > 0]
        negative = [f for f in feature_importances if f["importance"] < 0]
        
        summary = {
            "top_positive_features": [
                {
                    "feature": f["feature"],
                    "value": f["value"],
                    "shap_value": f["importance"]
                }
                for f in positive[:5]
            ],
            "top_negative_features": [
                {
                    "feature": f["feature"],
                    "value": f["value"],
                    "shap_value": f["importance"]
                }
                for f in negative[:3]
            ],
            "total_positive_contribution": sum(f["importance"] for f in positive),
            "total_negative_contribution": sum(f["importance"] for f in negative)
        }
        
        return summary
    
    def _split_features(self, feature_importances: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
        """Split features into contributors (positive) and contradictors (negative)"""
        contributors = [f for f in feature_importances if f["importance"] > 0.01]
        contradictors = [f for f in feature_importances if f["importance"] < -0.01]
        
        return contributors, contradictors
    
    def _generate_narrative(self, feature_importances: List[Dict], verdict: Dict) -> str:
        """
        Generate human-readable narrative explanation
        
        Example: "This session was classified as 'simulate' with high confidence (0.88) 
        because it contains SQL injection keywords and exhibits high request rate..."
        """
        session_id = verdict.get("session_id", "unknown")
        verdict_label = verdict.get("verdict", "unknown")
        final_score = verdict.get("final_score", 0.0)
        
        # Get top 3 contributors
        top_features = [f for f in feature_importances if f["importance"] > 0][:3]
        
        # Build narrative
        narrative_parts = [
            f"Session {session_id} was classified as '{verdict_label}' with score {final_score:.2f}."
        ]
        
        if top_features:
            reasons = []
            for feature in top_features:
                reason = self._feature_to_text(feature)
                if reason:
                    reasons.append(reason)
            
            if reasons:
                narrative_parts.append("Key indicators:")
                for i, reason in enumerate(reasons, 1):
                    narrative_parts.append(f"{i}. {reason}")
        
        # Add behavioral context
        behavioral_score = verdict.get("behavioral_score", 0)
        if behavioral_score > 0.7:
            narrative_parts.append(
                f"Behavioral analysis shows high anomaly score ({behavioral_score:.2f}), "
                "indicating unusual activity patterns."
            )
        
        # Add payload context
        payload_preds = verdict.get("payload_predictions", [])
        malicious_payloads = [p for p in payload_preds if p["class"] != "benign"]
        
        if malicious_payloads:
            attack_types = {p["class"] for p in malicious_payloads}
            narrative_parts.append(
                f"Detected {len(malicious_payloads)} malicious payload(s) "
                f"of types: {', '.join(attack_types)}."
            )
        
        return " ".join(narrative_parts)
    
    def _feature_to_text(self, feature: Dict) -> str:
        """Convert feature to human-readable description"""
        feature_name = feature["feature"]
        value = feature["value"]
        
        descriptions = {
            "contains_sql_keywords": "SQL injection keywords detected in payloads",
            "contains_xss_patterns": "Cross-site scripting (XSS) patterns found",
            "contains_cmd_patterns": "Command injection patterns detected",
            "max_payload_entropy": f"High payload entropy ({value:.1f}), suggesting obfuscation",
            "error_rate": f"High error rate ({value:.1%}), indicating probing behavior",
            "request_rate_per_min": f"Elevated request rate ({value:.0f}/min), potential scanning",
            "special_char_ratio": f"High special character usage ({value:.1%})",
            "ua_fingerprint_score": "User-Agent fingerprint changes detected",
            "has_poi_tag": "Previously tagged as Person of Interest (POI)",
            "prior_poi_count": f"Prior POI incidents: {int(value)}"
        }
        
        return descriptions.get(feature_name, f"{feature_name}: {value}")
    
    def export_for_review(self, explanation: Dict, output_path: str = None):
        """
        Export explanation in format suitable for SOC review
        
        Generates JSON + human-readable HTML report
        """
        try:
            if not output_path:
                output_dir = os.path.join(
                    os.path.dirname(__file__), '..', '..', 'data', 'explanations'
                )
                os.makedirs(output_dir, exist_ok=True)
                
                session_id = explanation.get("session_id", "unknown")
                output_path = os.path.join(output_dir, f"{session_id}_explanation.json")
            
            # Save JSON
            with open(output_path, 'w') as f:
                json.dump(explanation, f, indent=2)
            
            # Generate HTML report
            html_path = output_path.replace('.json', '.html')
            html_content = self._generate_html_report(explanation)
            
            with open(html_path, 'w') as f:
                f.write(html_content)
            
            logger.info(f"Explanation exported: {output_path}")
            
            return output_path
        
        except Exception as e:
            logger.error(f"Error exporting explanation: {e}", exc_info=True)
            return None
    
    def _generate_html_report(self, explanation: Dict) -> str:
        """Generate HTML report for human review"""
        session_id = explanation.get("session_id", "unknown")
        verdict = explanation.get("verdict", "unknown")
        score = explanation.get("final_score", 0.0)
        narrative = explanation.get("narrative", "")
        
        # Top contributors
        contributors = explanation.get("top_contributors", [])
        contributors_html = "<ul>"
        for contrib in contributors[:5]:
            contributors_html += f"<li><strong>{contrib['feature']}</strong>: {contrib['value']} (importance: {contrib['importance']:.3f})</li>"
        contributors_html += "</ul>"
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Explanation Report - {session_id}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .verdict {{ font-size: 24px; font-weight: bold; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .verdict.simulate {{ background: #f8d7da; color: #721c24; }}
        .verdict.tag {{ background: #fff3cd; color: #856404; }}
        .verdict.benign {{ background: #d4edda; color: #155724; }}
        .score {{ font-size: 20px; margin: 10px 0; }}
        .narrative {{ background: #e7f3ff; padding: 15px; border-left: 4px solid #007bff; margin: 20px 0; }}
        ul {{ line-height: 1.8; }}
        .footer {{ margin-top: 40px; color: #666; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Sentinel Analysis Report</h1>
        <p><strong>Session ID:</strong> {session_id}</p>
        <p><strong>Generated:</strong> {explanation.get('generated_at', 'N/A')}</p>
        
        <div class="verdict {verdict}">
            Verdict: {verdict.upper()}
        </div>
        
        <div class="score">
            Risk Score: {score:.2f} / 1.00
        </div>
        
        <h2>📊 Summary</h2>
        <div class="narrative">
            {narrative}
        </div>
        
        <h2>🔍 Top Contributing Features</h2>
        {contributors_html}
        
        <div class="footer">
            <p>Generated by Cerberus Sentinel AI • Explainability Engine</p>
            <p>This report uses SHAP-like feature importance analysis for model interpretability.</p>
        </div>
    </div>
</body>
</html>
"""
        return html


# CLI entry point
if __name__ == "__main__":
    engine = ExplainabilityEngine()
    
    # Example usage
    sample_features = {
        "contains_sql_keywords": 1,
        "contains_xss_patterns": 0,
        "contains_cmd_patterns": 0,
        "max_payload_entropy": 7.8,
        "error_rate": 0.6,
        "request_rate_per_min": 75,
        "special_char_ratio": 0.45,
        "n_payloads": 5
    }
    
    sample_verdict = {
        "session_id": "test_explain_001",
        "verdict": "simulate",
        "final_score": 0.88,
        "behavioral_score": 0.82,
        "payload_predictions": [
            {"class": "sql_injection", "confidence": 0.95}
        ]
    }
    
    explanation = engine.explain_verdict(sample_features, sample_verdict)
    
    print("\n=== Explanation ===\n")
    print(json.dumps(explanation, indent=2))
    
    # Export report
    engine.export_for_review(explanation)
    print("\nHTML report generated!")
