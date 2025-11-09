"""
Stage 8: Model Trainer - Automated retraining pipeline
Handles model training, validation, and promotion with gating
"""
import json
import os
from typing import Dict, List, Tuple
from datetime import datetime
import numpy as np

# ML libraries
try:
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.metrics import (
        classification_report, confusion_matrix,
        precision_score, recall_score, f1_score, roc_auc_score
    )
    import joblib
    SKLEARN_AVAILABLE = True
except ImportError:
    print("[WARNING] scikit-learn not installed")
    SKLEARN_AVAILABLE = False

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from sentinel.training.dataset_manager import DatasetManager
from sentinel.ml.payload_classifier import PayloadClassifier
from sentinel.ml.anomaly_detector import BehavioralAnomalyDetector
from shared.utils.logging import get_logger

logger = get_logger(__name__)


class ModelTrainer:
    """
    Automated model training and promotion pipeline
    
    Features:
    - Incremental and full retraining
    - Model validation with holdout test set
    - Metric-based gating (precision, recall, FPR)
    - Canary rollout support
    - Model registry with versioning
    """
    
    # Promotion thresholds
    PRECISION_THRESHOLD = 0.85
    RECALL_THRESHOLD = 0.80
    FPR_THRESHOLD = 0.05  # Max 5% false positive rate
    F1_THRESHOLD = 0.82
    
    def __init__(self, dataset_manager: DatasetManager = None):
        self.dataset_manager = dataset_manager or DatasetManager()
        self.model_registry_path = os.path.join(
            os.path.dirname(__file__), '..', '..', 'data', 'models', 'registry.json'
        )
        self.model_registry = self._load_registry()
        
        logger.info("Model trainer initialized")
    
    def train_payload_classifier(
        self,
        dataset_version: str = None,
        mode: str = "full"
    ) -> Dict:
        """
        Train payload classifier
        
        Args:
            dataset_version: Specific dataset version to use
            mode: "full" or "incremental"
            
        Returns:
            Training results with metrics
        """
        if not SKLEARN_AVAILABLE:
            logger.error("Cannot train: scikit-learn not available")
            return {"error": "sklearn_not_available"}
        
        try:
            logger.info(f"Training payload classifier: mode={mode}")
            
            # Load dataset
            X_train, y_train = self.dataset_manager.get_training_data(sample_type="payload")
            
            if len(X_train) < 20:
                logger.warning(f"Insufficient training data: {len(X_train)} samples")
                return {"error": "insufficient_data", "sample_count": len(X_train)}
            
            logger.info(f"Training data loaded: {len(X_train)} samples")
            
            # Initialize classifier
            classifier = PayloadClassifier()
            
            # Split for validation
            X_train_split, X_val, y_train_split, y_val = train_test_split(
                X_train, y_train, test_size=0.2, random_state=42, stratify=y_train
            )
            
            # Train
            training_data = list(zip(X_train_split, y_train_split))
            classifier.train(training_data)
            
            # Validate
            metrics = self._validate_classifier(classifier, X_val, y_val)
            
            # Check promotion criteria
            can_promote = self._check_promotion_criteria(metrics)
            
            # Save model with metadata
            model_metadata = {
                "model_type": "payload_classifier",
                "trained_at": datetime.utcnow().isoformat(),
                "dataset_version": dataset_version,
                "mode": mode,
                "training_samples": len(X_train_split),
                "validation_samples": len(X_val),
                "metrics": metrics,
                "can_promote": can_promote,
                "promotion_reason": self._get_promotion_reason(metrics, can_promote)
            }
            
            # Save to registry
            model_id = self._register_model(model_metadata)
            
            result = {
                "model_id": model_id,
                "status": "success",
                "can_promote": can_promote,
                **model_metadata
            }
            
            logger.info(
                f"Payload classifier training complete: "
                f"F1={metrics.get('f1', 0):.3f}, can_promote={can_promote}"
            )
            
            return result
        
        except Exception as e:
            logger.error(f"Error training payload classifier: {e}", exc_info=True)
            return {"error": str(e)}
    
    def train_anomaly_detector(self, dataset_version: str = None) -> Dict:
        """
        Train anomaly detector on benign sessions
        
        Args:
            dataset_version: Specific dataset version
            
        Returns:
            Training results
        """
        if not SKLEARN_AVAILABLE:
            return {"error": "sklearn_not_available"}
        
        try:
            logger.info("Training anomaly detector")
            
            # Load benign sessions
            samples = self.dataset_manager.get_dataset(
                sample_type="session",
                label="benign",
                split="train"
            )
            
            if len(samples) < 20:
                logger.warning(f"Insufficient benign samples: {len(samples)}")
                return {"error": "insufficient_data", "sample_count": len(samples)}
            
            # Extract features
            feature_samples = [s["data"] for s in samples]
            
            # Train
            detector = BehavioralAnomalyDetector()
            detector.train(feature_samples)
            
            # Validate (score on validation set)
            val_samples = self.dataset_manager.get_dataset(
                sample_type="session",
                split="validation"
            )
            
            metrics = self._validate_anomaly_detector(detector, val_samples)
            
            model_metadata = {
                "model_type": "anomaly_detector",
                "trained_at": datetime.utcnow().isoformat(),
                "dataset_version": dataset_version,
                "training_samples": len(samples),
                "metrics": metrics
            }
            
            model_id = self._register_model(model_metadata)
            
            logger.info(f"Anomaly detector training complete: {model_id}")
            
            return {
                "model_id": model_id,
                "status": "success",
                **model_metadata
            }
        
        except Exception as e:
            logger.error(f"Error training anomaly detector: {e}", exc_info=True)
            return {"error": str(e)}
    
    def _validate_classifier(
        self,
        classifier: PayloadClassifier,
        X_val: List[str],
        y_val: List[str]
    ) -> Dict:
        """
        Validate classifier and compute metrics
        
        Returns:
            Metrics dict with precision, recall, F1, FPR, etc.
        """
        try:
            # Predict on validation set
            y_pred = []
            y_proba = []
            
            for payload in X_val:
                pred = classifier.predict(payload)
                y_pred.append(pred["class"])
                y_proba.append(pred["confidence"])
            
            # Calculate metrics
            # For multi-class, use weighted averaging
            precision = precision_score(y_val, y_pred, average='weighted', zero_division=0)
            recall = recall_score(y_val, y_pred, average='weighted', zero_division=0)
            f1 = f1_score(y_val, y_pred, average='weighted', zero_division=0)
            
            # False Positive Rate (benign classified as attack)
            # Compute for binary: benign vs. any attack
            y_val_binary = ['benign' if y == 'benign' else 'attack' for y in y_val]
            y_pred_binary = ['benign' if y == 'benign' else 'attack' for y in y_pred]
            
            cm = confusion_matrix(y_val_binary, y_pred_binary, labels=['benign', 'attack'])
            
            if cm.shape == (2, 2):
                tn, fp, fn, tp = cm.ravel()
                fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
                tpr = tp / (tp + fn) if (tp + fn) > 0 else 0
            else:
                fpr = 0
                tpr = 0
            
            metrics = {
                "precision": float(precision),
                "recall": float(recall),
                "f1": float(f1),
                "fpr": float(fpr),
                "tpr": float(tpr),
                "accuracy": float(np.mean(np.array(y_val) == np.array(y_pred))),
                "validation_samples": len(y_val)
            }
            
            # Detailed classification report
            report = classification_report(y_val, y_pred, output_dict=True, zero_division=0)
            metrics["per_class_metrics"] = report
            
            logger.info(
                f"Validation metrics: Precision={precision:.3f}, Recall={recall:.3f}, "
                f"F1={f1:.3f}, FPR={fpr:.3f}"
            )
            
            return metrics
        
        except Exception as e:
            logger.error(f"Error validating classifier: {e}", exc_info=True)
            return {}
    
    def _validate_anomaly_detector(
        self,
        detector: BehavioralAnomalyDetector,
        val_samples: List[Dict]
    ) -> Dict:
        """Validate anomaly detector"""
        try:
            scores = []
            labels = []
            
            for sample in val_samples:
                features = sample["data"]
                label = sample["label"]
                
                score = detector.score(features)
                scores.append(score)
                labels.append(1 if label != "benign" else 0)
            
            # Calculate AUC if possible
            try:
                if len(set(labels)) > 1:
                    auc = roc_auc_score(labels, scores)
                else:
                    auc = 0.0
            except:
                auc = 0.0
            
            metrics = {
                "auc": float(auc),
                "avg_anomaly_score": float(np.mean(scores)),
                "validation_samples": len(val_samples)
            }
            
            return metrics
        
        except Exception as e:
            logger.error(f"Error validating anomaly detector: {e}", exc_info=True)
            return {}
    
    def _check_promotion_criteria(self, metrics: Dict) -> bool:
        """
        Check if model meets promotion criteria
        
        Requirements:
        - Precision >= PRECISION_THRESHOLD
        - Recall >= RECALL_THRESHOLD
        - FPR <= FPR_THRESHOLD
        - F1 >= F1_THRESHOLD
        """
        precision = metrics.get("precision", 0)
        recall = metrics.get("recall", 0)
        f1 = metrics.get("f1", 0)
        fpr = metrics.get("fpr", 1.0)
        
        criteria_met = (
            precision >= self.PRECISION_THRESHOLD and
            recall >= self.RECALL_THRESHOLD and
            fpr <= self.FPR_THRESHOLD and
            f1 >= self.F1_THRESHOLD
        )
        
        return criteria_met
    
    def _get_promotion_reason(self, metrics: Dict, can_promote: bool) -> str:
        """Generate human-readable promotion reason"""
        if can_promote:
            return "All promotion criteria met"
        
        failures = []
        
        if metrics.get("precision", 0) < self.PRECISION_THRESHOLD:
            failures.append(
                f"Precision {metrics.get('precision', 0):.3f} < {self.PRECISION_THRESHOLD}"
            )
        
        if metrics.get("recall", 0) < self.RECALL_THRESHOLD:
            failures.append(
                f"Recall {metrics.get('recall', 0):.3f} < {self.RECALL_THRESHOLD}"
            )
        
        if metrics.get("fpr", 1.0) > self.FPR_THRESHOLD:
            failures.append(
                f"FPR {metrics.get('fpr', 1.0):.3f} > {self.FPR_THRESHOLD}"
            )
        
        if metrics.get("f1", 0) < self.F1_THRESHOLD:
            failures.append(
                f"F1 {metrics.get('f1', 0):.3f} < {self.F1_THRESHOLD}"
            )
        
        return "Criteria not met: " + "; ".join(failures)
    
    def _register_model(self, metadata: Dict) -> str:
        """Register model in model registry"""
        model_id = f"{metadata['model_type']}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        
        metadata["model_id"] = model_id
        
        # Update registry
        self.model_registry[model_id] = metadata
        
        # Save registry
        os.makedirs(os.path.dirname(self.model_registry_path), exist_ok=True)
        with open(self.model_registry_path, 'w') as f:
            json.dump(self.model_registry, f, indent=2)
        
        logger.info(f"Model registered: {model_id}")
        
        return model_id
    
    def _load_registry(self) -> Dict:
        """Load model registry"""
        if os.path.exists(self.model_registry_path):
            with open(self.model_registry_path, 'r') as f:
                return json.load(f)
        return {}
    
    def promote_model(self, model_id: str, canary_percent: int = 1) -> Dict:
        """
        Promote model to production
        
        Args:
            model_id: Model ID to promote
            canary_percent: Start with canary rollout (1%, 10%, 100%)
            
        Returns:
            Promotion result
        """
        try:
            if model_id not in self.model_registry:
                return {"error": "model_not_found"}
            
            metadata = self.model_registry[model_id]
            
            if not metadata.get("can_promote", False):
                return {
                    "error": "promotion_criteria_not_met",
                    "reason": metadata.get("promotion_reason")
                }
            
            # Update promotion status
            metadata["promoted_at"] = datetime.utcnow().isoformat()
            metadata["canary_percent"] = canary_percent
            metadata["status"] = "promoted"
            
            self.model_registry[model_id] = metadata
            
            # Save registry
            with open(self.model_registry_path, 'w') as f:
                json.dump(self.model_registry, f, indent=2)
            
            logger.info(f"Model promoted: {model_id} (canary={canary_percent}%)")
            
            return {
                "status": "success",
                "model_id": model_id,
                "canary_percent": canary_percent,
                "promoted_at": metadata["promoted_at"]
            }
        
        except Exception as e:
            logger.error(f"Error promoting model: {e}", exc_info=True)
            return {"error": str(e)}


# CLI entry point
if __name__ == "__main__":
    from sentinel.ml.payload_classifier import generate_synthetic_training_data
    
    # Setup dataset
    dataset_mgr = DatasetManager()
    
    # Add synthetic training data
    training_data = generate_synthetic_training_data()
    for payload, label in training_data:
        dataset_mgr.add_labeled_sample(
            sample_type="payload",
            data=payload,
            label=label,
            source="synthetic"
        )
    
    # Train model
    trainer = ModelTrainer(dataset_mgr)
    result = trainer.train_payload_classifier()
    
    print("\n=== Training Result ===\n")
    print(json.dumps(result, indent=2))
    
    # Promote if criteria met
    if result.get("can_promote"):
        promote_result = trainer.promote_model(result["model_id"], canary_percent=10)
        print("\n=== Promotion Result ===\n")
        print(json.dumps(promote_result, indent=2))
