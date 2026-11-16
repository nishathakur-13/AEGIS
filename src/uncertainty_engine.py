import os
import sys
import numpy as np

# Ensure root directory is in Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import THREAT_HIGH_THRESHOLD, UNCERTAINTY_HIGH_THRESHOLD

class EpistemicUncertaintyEngine:
    """
    Evaluates composite threat probability and model variance (epistemic uncertainty)
    across heterogeneous ensemble predictions.
    """
    def __init__(self, threat_threshold: float = THREAT_HIGH_THRESHOLD, uncertainty_threshold: float = UNCERTAINTY_HIGH_THRESHOLD):
        self.threat_threshold = threat_threshold
        self.uncertainty_threshold = uncertainty_threshold

    def evaluate_uncertainty(self, model_probabilities: dict) -> dict:
        """
        Calculates mean probability, variance, and routes decision status.
        """
        probs = list(model_probabilities.values())
        
        # 1. Composite Threat Score (Mean Probability)
        threat_score = float(np.mean(probs))
        
        # 2. Epistemic Uncertainty (Model Variance)
        uncertainty_variance = float(np.var(probs))
        
        # 3. Standard Deviation for visual gauge
        std_dev = float(np.std(probs))

        # 4. Routing Decision Logic
        if threat_score >= self.threat_threshold and uncertainty_variance < self.uncertainty_threshold:
            decision = 'HIGH_CONFIDENCE_THREAT'
            action = 'TRIGGER_MITIGATION_AND_PRE_VALIDATION'
        elif threat_score >= self.threat_threshold and uncertainty_variance >= self.uncertainty_threshold:
            decision = 'HIGH_UNCERTAINTY_ANOMALY'
            action = 'ESCALATE_TELEMETRY_LOGGING_AND_ALERT_SOC'
        elif threat_score < 0.30 and uncertainty_variance < self.uncertainty_threshold:
            decision = 'BENIGN_TRAFFIC'
            action = 'PASS_NORMAL_OPERATIONS'
        else:
            decision = 'AMBIGUOUS_ACTIVITY'
            action = 'MONITOR_FLOW'

        return {
            'composite_threat_score': threat_score,
            'epistemic_uncertainty_variance': uncertainty_variance,
            'standard_deviation': std_dev,
            'decision_verdict': decision,
            'recommended_action': action,
            'individual_model_probs': model_probabilities
        }

if __name__ == '__main__':
    from src.red_team import RedTeamSimulator
    from src.blue_team import BlueTeamEnsemble

    red_agent = RedTeamSimulator()
    blue_ensemble = BlueTeamEnsemble()
    uncertainty_engine = EpistemicUncertaintyEngine()

    # Test with Simulated Attack
    attack_payload = red_agent.generate_attack_payload('TELEMETRY_SPOOFING')
    df_attack = red_agent.payload_to_dataframe(attack_payload)

    probs = blue_ensemble.predict_probabilities(df_attack)
    eval_result = uncertainty_engine.evaluate_uncertainty(probs)

    print("📊 Epistemic Uncertainty Engine Evaluation Results:")
    print(f"🎯 Composite Threat Score : {eval_result['composite_threat_score'] * 100:.2f}%")
    print(f"📉 Model Disagreement (σ²): {eval_result['epistemic_uncertainty_variance']:.6f}")
    print(f"🏷️ Decision Verdict       : {eval_result['decision_verdict']}")
    print(f"⚡ Recommended Action     : {eval_result['recommended_action']}")