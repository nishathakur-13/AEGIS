import os
import sys
import pandas as pd
import numpy as np
import joblib

# Ensure root directory is in Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
from xgboost import XGBClassifier
from catboost import CatBoostClassifier

from config.settings import BASE_DIR, FEATURE_COLUMNS, BATADAL_FEATURE_COLUMNS, ACTIVE_DATASET

class BlueTeamEnsemble:
    """
    Heterogeneous ML Ensemble consisting of Random Forest, Extra Trees,
    XGBoost, and CatBoost models for ICS / grid anomaly detection.

    Supports two dataset modes:
      - 'synthetic' : original 8-feature grid telemetry dataset
      - 'batadal'   : 14-feature physics-informed BATADAL real-world ICS dataset
    """
    def __init__(self, dataset_mode: str = None):
        # Auto-detect mode from settings if not specified
        self.dataset_mode = dataset_mode or ACTIVE_DATASET
        self.feature_columns = (
            BATADAL_FEATURE_COLUMNS if self.dataset_mode == 'batadal'
            else FEATURE_COLUMNS
        )
        self.models = {
            'random_forest': RandomForestClassifier(n_estimators=200, random_state=42),
            'extra_trees':   ExtraTreesClassifier(n_estimators=200, random_state=42),
            'xgboost':       XGBClassifier(n_estimators=200, eval_metric='logloss', random_state=42),
            'catboost':      CatBoostClassifier(iterations=200, verbose=0, random_state=42)
        }
        self.is_trained = False
        self.scaler = None
        self.models_dir = os.path.join(BASE_DIR, 'src', 'saved_models')
        self.scaler_path = os.path.join(self.models_dir, 'batadal_scaler.joblib')

    def _load_scaler(self):
        """Load the BATADAL StandardScaler if it exists on disk."""
        if self.dataset_mode == 'batadal' and os.path.exists(self.scaler_path):
            self.scaler = joblib.load(self.scaler_path)

    def train_models(self, data_path: str = None):
        """
        Trains all 4 ML models on the configured dataset.
        For BATADAL mode, expects a feature-engineered DataFrame or CSV.
        For synthetic mode, uses the original synthetic_logs.csv.
        """
        if data_path is None:
            data_path = os.path.join(BASE_DIR, 'data', 'synthetic_logs.csv')

        if not os.path.exists(data_path):
            raise FileNotFoundError(f"Dataset not found at {data_path}. Run the data generation script first!")

        df = pd.read_csv(data_path)
        X = df[self.feature_columns]
        y = df['is_threat']

        print(f"⚙️ Training Heterogeneous ML Ensemble [{self.dataset_mode.upper()} mode]...")
        for name, model in self.models.items():
            model.fit(X, y)
            print(f"  └── Trained: {name.upper()}")

        self.is_trained = True
        self.save_models()
        print("✅ All 4 models trained and saved successfully.")

    def save_models(self):
        """Saves trained model artifacts to disk."""
        os.makedirs(self.models_dir, exist_ok=True)
        for name, model in self.models.items():
            joblib.dump(model, os.path.join(self.models_dir, f"{name}.joblib"))

    def load_models(self):
        """Loads trained model artifacts from disk if available."""
        if not os.path.exists(self.models_dir):
            return False

        try:
            for name in self.models.keys():
                model_path = os.path.join(self.models_dir, f"{name}.joblib")
                self.models[name] = joblib.load(model_path)
            self.is_trained = True
            self._load_scaler()   # load scaler for BATADAL mode
            return True
        except Exception:
            return False

    def _prepare_input(self, X_sample: pd.DataFrame) -> np.ndarray:
        """Select the correct feature columns and apply scaler if needed."""
        X_input = X_sample[self.feature_columns]
        if self.scaler is not None:
            return self.scaler.transform(X_input)
        return X_input.values

    def predict_probabilities(self, X_sample: pd.DataFrame) -> dict:
        """
        Runs inference across all 4 ensemble models and returns individual
        threat probabilities (0.0 – 1.0).
        """
        if not self.is_trained:
            loaded = self.load_models()
            if not loaded:
                print("⚠️ Models not found on disk. Training new ensemble...")
                self.train_models()

        X_input = self._prepare_input(X_sample)
        probabilities = {}

        for name, model in self.models.items():
            prob_threat = float(model.predict_proba(X_input)[0][1])
            probabilities[name] = prob_threat

        return probabilities

if __name__ == '__main__':
    from src.red_team import RedTeamSimulator

    # Test Blue Team Ensemble Inference
    ensemble = BlueTeamEnsemble()
    ensemble.train_models()

    red_agent = RedTeamSimulator()
    attack_sample = red_agent.generate_attack_payload('PRIVILEGE_ESCALATION')
    df_attack = red_agent.payload_to_dataframe(attack_sample)

    print("\n🧠 Evaluating Attack Payload across Ensemble:")
    probs = ensemble.predict_probabilities(df_attack)
    for model_name, prob in probs.items():
        print(f"  ├── {model_name.upper():<15}: {prob * 100:.2f}% Threat Probability")