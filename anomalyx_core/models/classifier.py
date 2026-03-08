"""
ML Model Classifier for Network Intrusion Detection
Uses pre-trained Random Forest model from training notebooks
"""
import joblib
import numpy as np
import pandas as pd
import os
import warnings
from pathlib import Path

warnings.filterwarnings('ignore')

class IDSClassifier:
    """Intrusion Detection System Classifier using trained Random Forest Pipeline"""
    
    def __init__(self, model_path=None, label_encoder_path=None, selected_features_path=None):
        self.model = None
        self.label_encoder = None
        self.selected_features = None
        
        # These are the features expected by the trained model
        self.selected_features_list = [
            'src_bytes', 'same_srv_rate', 'flag', 'dst_host_serror_rate', 
            'srv_serror_rate', 'dst_host_same_srv_rate', 'diff_srv_rate', 
            'count', 'dst_host_srv_serror_rate', 'serror_rate', 
            'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 
            'dst_bytes', 'dst_host_diff_srv_rate', 'protocol_type', 
            'dst_host_srv_count', 'service', 'srv_count', 'dst_host_count', 
            'dst_host_rerror_rate'
        ]
        
        # Map attack labels to categories
        self.attack_categories = {
            'normal': 'normal',
            'back': 'DoS',
            'land': 'DoS',
            'neptune': 'DoS',
            'pod': 'DoS',
            'smurf': 'DoS',
            'teardrop': 'DoS',
            'mailbomb': 'DoS',
            'apache2': 'DoS',
            'processtable': 'DoS',
            'udpstorm': 'DoS',
            'satan': 'Probe',
            'ipsweep': 'Probe',
            'nmap': 'Probe',
            'portsweep': 'Probe',
            'mscan': 'Probe',
            'saint': 'Probe',
            'guess_passwd': 'R2L',
            'ftp_write': 'R2L',
            'imap': 'R2L',
            'phf': 'R2L',
            'multihop': 'R2L',
            'warezmaster': 'R2L',
            'warezclient': 'R2L',
            'spy': 'R2L',
            'xlock': 'R2L',
            'xsnoop': 'R2L',
            'snmpguess': 'R2L',
            'snmpgetattack': 'R2L',
            'httptunnel': 'R2L',
            'sendmail': 'R2L',
            'named': 'R2L',
            'shellcode': 'U2R',
            'loadmodule': 'U2R',
            'perl': 'U2R',
            'rootkit': 'U2R',
            'buffer_overflow': 'U2R',
            'xterm': 'U2R',
            'ps': 'U2R',
        }
        
        # Try to load pre-trained models
        if model_path and os.path.exists(model_path):
            self.load_model(model_path, label_encoder_path, selected_features_path)
        else:
            self.find_and_load_models()
    
    def find_and_load_models(self):
        """Automatically find and load models from models directory"""
        model_dir = Path(__file__).resolve().parent

        # Optional explicit external model dir (for custom production models).
        env_dir = os.getenv("ANOMALYX_MODEL_DIR", "").strip()
        candidate_dirs = []
        if env_dir:
            candidate_dirs.append(Path(env_dir))
        candidate_dirs.append(model_dir)

        for cdir in candidate_dirs:
            if not cdir.exists() or not cdir.is_dir():
                continue

            model_candidates = sorted(
                [p for p in cdir.glob("*.pkl") if "random_forest" in p.name.lower()]
            )
            if not model_candidates:
                continue

            model_path = str(model_candidates[0])
            label_encoder_path = str(cdir / "label_encoder.pkl")
            selected_features_path = str(cdir / "selected_features.pkl")
            self.load_model(model_path, label_encoder_path, selected_features_path)

            if self.model is not None:
                print(f"✅ IDS model runtime source: {cdir}")
                return

        print("⚠️  No pre-trained model found in package/runtime path. Using heuristic classification.")
    
    def load_model(self, model_path, label_encoder_path=None, selected_features_path=None):
        """Load pre-trained model and related files"""
        try:
            self.model = joblib.load(model_path)
            print(f"✅ Loaded pipeline model from: {os.path.basename(model_path)}")
            
            if label_encoder_path and os.path.exists(label_encoder_path):
                self.label_encoder = joblib.load(label_encoder_path)
                print(f"✅ Loaded label encoder")
            
            if selected_features_path and os.path.exists(selected_features_path):
                self.selected_features = joblib.load(selected_features_path)
                print(f"✅ Loaded selected features")
            
        except Exception as e:
            print(f"⚠️  Error loading model: {e}")
            print(f"Will use heuristic classification as fallback")
            self.model = None
    
    def classify_packet(self, features_dict):
        """
        Classify a packet using trained model or heuristics
        
        Args:
            features_dict: Dictionary with packet features
            
        Returns:
            Dictionary with classification results
        """
        try:
            if self.model is not None:
                return self._ml_classify(features_dict)
            else:
                return self._heuristic_classify(features_dict)
        except Exception as e:
            print(f"Classification error: {e}")
            return self._heuristic_classify(features_dict)
    
    def _ml_classify(self, features_dict):
        """Classify using trained ML model pipeline"""
        try:
            # Get selected features - determine dynamically if we have them
            if self.selected_features:
                feature_cols = self.selected_features
            else:
                feature_cols = self.selected_features_list
            
            # Create a DataFrame with the required columns
            # Fill missing columns with default values
            row_dict = {}
            for col in feature_cols:
                if col in features_dict:
                    row_dict[col] = features_dict[col]
                else:
                    # Default values for missing features
                    row_dict[col] = 0
            
            df_sample = pd.DataFrame([row_dict])
            
            # Use the pipeline to predict
            prediction = self.model.predict(df_sample)[0]
            probabilities = self.model.predict_proba(df_sample)[0]
            confidence = max(probabilities) * 100
            
            # Convert encoded label back to attack type
            if self.label_encoder:
                attack_type = self.label_encoder.inverse_transform([prediction])[0]
            else:
                attack_type = str(prediction)
            
            return {
                'attack_type': attack_type,
                'confidence': round(confidence, 2),
                'category': self.attack_categories.get(attack_type, 'Unknown')
            }
        except Exception as e:
            print(f"ML classification failed: {e}, using heuristics")
            return self._heuristic_classify(features_dict)
    
    def _heuristic_classify(self, features_dict):
        """Heuristic-based classification for fallback"""
        src_bytes = features_dict.get('src_bytes', 0)
        dst_bytes = features_dict.get('dst_bytes', 0)
        count = features_dict.get('count', 0)
        srv_count = features_dict.get('srv_count', 0)
        serror_rate = features_dict.get('serror_rate', 0)
        
        attack_type = 'normal'
        confidence = 95
        
        # DoS detection
        if count > 10 and serror_rate > 0.5:
            attack_type = 'neptune'
            confidence = 85
        
        # Port scan detection
        elif srv_count > 30 and src_bytes < 100:
            attack_type = 'mscan'
            confidence = 80
        
        # R2L detection
        elif dst_bytes > src_bytes * 5 and count < 5:
            attack_type = 'httptunnel'
            confidence = 75
        
        return {
            'attack_type': attack_type,
            'confidence': confidence,
            'category': self.attack_categories.get(attack_type, 'Unknown')
        }

# Global classifier instance
_classifier = None

def get_classifier():
    """Get or initialize the global classifier"""
    global _classifier
    if _classifier is None:
        _classifier = IDSClassifier()
    
    return _classifier
