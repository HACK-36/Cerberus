"""
Stage 8: Dataset Manager - Manages training datasets with versioning
Collects labeled samples for model retraining
"""
import json
import os
import hashlib
from typing import Dict, List, Tuple
from datetime import datetime
from pathlib import Path

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from shared.utils.logging import get_logger

logger = get_logger(__name__)


class DatasetManager:
    """
    Manages training datasets with versioning and labeling
    
    Features:
    - Store labeled samples (positive/negative)
    - Version control for datasets
    - Train/validation/test splits
    - Dataset statistics and quality metrics
    - Export in standard formats (JSON, CSV, DVC-compatible)
    """
    
    def __init__(self, base_path: str = None):
        self.base_path = base_path or os.path.join(
            os.path.dirname(__file__), '..', '..', 'data', 'datasets'
        )
        os.makedirs(self.base_path, exist_ok=True)
        
        # Initialize dataset registry
        self.registry_path = os.path.join(self.base_path, 'registry.json')
        self.registry = self._load_registry()
        
        logger.info(f"Dataset manager initialized: {self.base_path}")
    
    def add_labeled_sample(
        self,
        sample_type: str,
        data: Dict,
        label: str,
        confidence: float = 1.0,
        source: str = "manual",
        metadata: Dict = None
    ):
        """
        Add a labeled sample to the dataset
        
        Args:
            sample_type: "payload" or "session"
            data: Raw data (payload string or session features)
            label: Label (attack class or "benign")
            confidence: Labeling confidence (0-1)
            source: Source of label (manual, simulation, human_review)
            metadata: Additional metadata
        """
        try:
            sample = {
                "id": self._generate_sample_id(data),
                "type": sample_type,
                "data": data,
                "label": label,
                "confidence": confidence,
                "source": source,
                "metadata": metadata or {},
                "created_at": datetime.utcnow().isoformat()
            }
            
            # Determine dataset split (90% train, 10% validation)
            split = "train" if hash(sample["id"]) % 10 < 9 else "validation"
            
            # Save to appropriate file
            self._save_sample(sample, split)
            
            # Update registry
            self._update_registry(sample_type, label, split)
            
            logger.info(
                f"Added labeled sample: type={sample_type}, label={label}, "
                f"split={split}, source={source}"
            )
        
        except Exception as e:
            logger.error(f"Error adding labeled sample: {e}", exc_info=True)
    
    def add_from_simulation_result(self, sim_result: Dict, verdict: str):
        """
        Add sample from simulation result
        
        Automatically label based on simulation verdict
        """
        session_id = sim_result.get("session_id", "unknown")
        payload = sim_result.get("payload", {})
        
        # Determine label
        if verdict == "exploit_possible":
            label = payload.get("type", "attack")
            confidence = 0.95  # High confidence from simulation
            source = "simulation_confirmed"
        elif verdict == "exploit_improbable":
            label = "benign"
            confidence = 0.8
            source = "simulation_negative"
        else:
            label = "uncertain"
            confidence = 0.5
            source = "simulation_unclear"
        
        # Add payload sample
        if payload.get("value"):
            self.add_labeled_sample(
                sample_type="payload",
                data=payload.get("value"),
                label=label,
                confidence=confidence,
                source=source,
                metadata={
                    "session_id": session_id,
                    "simulation_score": sim_result.get("exploit_score", 0),
                    "attack_type": payload.get("type")
                }
            )
    
    def add_false_positive(self, sample: Dict, reviewer: str):
        """
        Add a false positive sample (human feedback)
        
        These are critical for reducing FP rate
        """
        self.add_labeled_sample(
            sample_type="payload",
            data=sample.get("payload", ""),
            label="benign",
            confidence=1.0,  # Human verified
            source="human_review_fp",
            metadata={
                "reviewer": reviewer,
                "original_prediction": sample.get("original_label"),
                "session_id": sample.get("session_id"),
                "review_notes": sample.get("notes", "")
            }
        )
        
        logger.info(f"False positive added by {reviewer}")
    
    def get_dataset(
        self,
        sample_type: str = None,
        split: str = "train",
        label: str = None
    ) -> List[Dict]:
        """
        Retrieve dataset samples
        
        Args:
            sample_type: Filter by type (payload/session)
            split: train/validation/test
            label: Filter by label
            
        Returns:
            List of samples
        """
        try:
            split_dir = os.path.join(self.base_path, split)
            
            if not os.path.exists(split_dir):
                return []
            
            samples = []
            
            # Load all samples from split directory
            for filename in os.listdir(split_dir):
                if not filename.endswith('.json'):
                    continue
                
                filepath = os.path.join(split_dir, filename)
                with open(filepath, 'r') as f:
                    sample = json.load(f)
                
                # Apply filters
                if sample_type and sample.get("type") != sample_type:
                    continue
                
                if label and sample.get("label") != label:
                    continue
                
                samples.append(sample)
            
            logger.info(
                f"Retrieved {len(samples)} samples: "
                f"type={sample_type}, split={split}, label={label}"
            )
            
            return samples
        
        except Exception as e:
            logger.error(f"Error retrieving dataset: {e}", exc_info=True)
            return []
    
    def get_training_data(
        self,
        sample_type: str = "payload"
    ) -> Tuple[List[str], List[str]]:
        """
        Get training data in (X, y) format
        
        Returns:
            (data_list, labels_list)
        """
        samples = self.get_dataset(sample_type=sample_type, split="train")
        
        X = [s["data"] for s in samples]
        y = [s["label"] for s in samples]
        
        return X, y
    
    def create_version(self, version_name: str, description: str = "") -> Dict:
        """
        Create a versioned snapshot of current dataset
        
        Returns:
            Version metadata
        """
        try:
            version = {
                "name": version_name,
                "created_at": datetime.utcnow().isoformat(),
                "description": description,
                "stats": self.get_statistics(),
                "checksum": self._compute_dataset_checksum()
            }
            
            # Save version info
            versions_dir = os.path.join(self.base_path, 'versions')
            os.makedirs(versions_dir, exist_ok=True)
            
            version_file = os.path.join(versions_dir, f"{version_name}.json")
            with open(version_file, 'w') as f:
                json.dump(version, f, indent=2)
            
            logger.info(f"Dataset version created: {version_name}")
            
            return version
        
        except Exception as e:
            logger.error(f"Error creating version: {e}", exc_info=True)
            return {}
    
    def get_statistics(self) -> Dict:
        """
        Get dataset statistics
        
        Returns:
            Stats dict with counts, distributions, quality metrics
        """
        try:
            stats = {
                "total_samples": 0,
                "by_split": {},
                "by_type": {},
                "by_label": {},
                "by_source": {},
                "quality_metrics": {}
            }
            
            # Count samples
            for split in ["train", "validation", "test"]:
                samples = self.get_dataset(split=split)
                stats["by_split"][split] = len(samples)
                stats["total_samples"] += len(samples)
                
                for sample in samples:
                    # Count by type
                    sample_type = sample.get("type", "unknown")
                    stats["by_type"][sample_type] = stats["by_type"].get(sample_type, 0) + 1
                    
                    # Count by label
                    label = sample.get("label", "unknown")
                    stats["by_label"][label] = stats["by_label"].get(label, 0) + 1
                    
                    # Count by source
                    source = sample.get("source", "unknown")
                    stats["by_source"][source] = stats["by_source"].get(source, 0) + 1
            
            # Quality metrics
            stats["quality_metrics"] = self._calculate_quality_metrics()
            
            return stats
        
        except Exception as e:
            logger.error(f"Error calculating statistics: {e}", exc_info=True)
            return {}
    
    def export_to_csv(self, output_path: str, sample_type: str = "payload"):
        """Export dataset to CSV format"""
        try:
            import csv
            
            samples = self.get_dataset(sample_type=sample_type)
            
            with open(output_path, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=["id", "data", "label", "confidence", "source"])
                writer.writeheader()
                
                for sample in samples:
                    writer.writerow({
                        "id": sample["id"],
                        "data": str(sample["data"]),
                        "label": sample["label"],
                        "confidence": sample["confidence"],
                        "source": sample["source"]
                    })
            
            logger.info(f"Dataset exported to CSV: {output_path}")
        
        except Exception as e:
            logger.error(f"Error exporting to CSV: {e}", exc_info=True)
    
    def _save_sample(self, sample: Dict, split: str):
        """Save sample to appropriate split directory"""
        split_dir = os.path.join(self.base_path, split)
        os.makedirs(split_dir, exist_ok=True)
        
        filename = f"{sample['id']}.json"
        filepath = os.path.join(split_dir, filename)
        
        with open(filepath, 'w') as f:
            json.dump(sample, f, indent=2)
    
    def _generate_sample_id(self, data) -> str:
        """Generate unique sample ID"""
        data_str = json.dumps(data, sort_keys=True) if isinstance(data, dict) else str(data)
        hash_obj = hashlib.sha256(data_str.encode())
        return f"sample_{hash_obj.hexdigest()[:16]}"
    
    def _update_registry(self, sample_type: str, label: str, split: str):
        """Update dataset registry"""
        key = f"{sample_type}_{label}_{split}"
        self.registry[key] = self.registry.get(key, 0) + 1
        self.registry["last_updated"] = datetime.utcnow().isoformat()
        
        with open(self.registry_path, 'w') as f:
            json.dump(self.registry, f, indent=2)
    
    def _load_registry(self) -> Dict:
        """Load dataset registry"""
        if os.path.exists(self.registry_path):
            with open(self.registry_path, 'r') as f:
                return json.load(f)
        return {}
    
    def _compute_dataset_checksum(self) -> str:
        """Compute checksum of entire dataset"""
        hasher = hashlib.sha256()
        
        for split in ["train", "validation", "test"]:
            samples = self.get_dataset(split=split)
            for sample in sorted(samples, key=lambda s: s["id"]):
                sample_str = json.dumps(sample, sort_keys=True)
                hasher.update(sample_str.encode())
        
        return hasher.hexdigest()
    
    def _calculate_quality_metrics(self) -> Dict:
        """Calculate dataset quality metrics"""
        train_samples = self.get_dataset(split="train")
        
        if not train_samples:
            return {}
        
        # Class balance
        labels = [s["label"] for s in train_samples]
        label_counts = {label: labels.count(label) for label in set(labels)}
        max_count = max(label_counts.values())
        min_count = min(label_counts.values())
        balance_ratio = min_count / max_count if max_count > 0 else 0
        
        # Confidence distribution
        confidences = [s.get("confidence", 0) for s in train_samples]
        avg_confidence = sum(confidences) / len(confidences)
        
        # Human-verified ratio
        human_verified = sum(1 for s in train_samples if "human" in s.get("source", ""))
        human_ratio = human_verified / len(train_samples)
        
        return {
            "class_balance_ratio": balance_ratio,
            "avg_labeling_confidence": avg_confidence,
            "human_verified_ratio": human_ratio,
            "min_samples_per_class": min_count,
            "max_samples_per_class": max_count
        }


# CLI entry point
if __name__ == "__main__":
    manager = DatasetManager()
    
    # Example: Add some samples
    manager.add_labeled_sample(
        sample_type="payload",
        data="1' OR '1'='1",
        label="sql_injection",
        source="manual"
    )
    
    manager.add_labeled_sample(
        sample_type="payload",
        data="normal user input",
        label="benign",
        source="manual"
    )
    
    # Get statistics
    stats = manager.get_statistics()
    print("\n=== Dataset Statistics ===\n")
    print(json.dumps(stats, indent=2))
    
    # Create version
    version = manager.create_version("v2025-11-08", "Initial dataset")
    print(f"\nVersion created: {version['name']}")
