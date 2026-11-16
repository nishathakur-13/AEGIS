import os
import sys
import json
import time

# Ensure root directory is in Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import BASE_DIR, COMPLIANCE_MAP

class ComplianceAuditLogger:
    """
    Logs all security events, ML predictions, sandbox pre-validations,
    and human approvals in structured format mapped to European regulatory frameworks.
    """
    def __init__(self):
        self.logs_dir = os.path.join(BASE_DIR, 'logs')
        os.makedirs(self.logs_dir, exist_ok=True)
        self.log_file = os.path.join(self.logs_dir, 'audit_compliance_trail.json')

    def log_event(self, attack_payload: dict, uncertainty_eval: dict, patch_report: dict, human_approval_status: str) -> dict:
        """
        Creates and appends a compliance log entry.
        """
        audit_entry = {
            'event_id': f"AUDIT_{int(time.time() * 1000)}",
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            'target_node': attack_payload['target_node'],
            'attack_scenario': {
                'mitre_id': attack_payload['mitre_id'],
                'attack_name': attack_payload['attack_name'],
                'severity': attack_payload['severity']
            },
            'ml_ensemble_analytics': {
                'composite_threat_score_pct': round(uncertainty_eval['composite_threat_score'] * 100, 2),
                'epistemic_uncertainty_variance': round(uncertainty_eval['epistemic_uncertainty_variance'], 6),
                'model_predictions': uncertainty_eval['individual_model_probs']
            },
            'digital_twin_validation': {
                'patch_id': patch_report['patch_id'],
                'security_gain_pct': patch_report['security_gain_pct'],
                'operational_disruption_pct': patch_report['grid_disruption_pct'],
                'sandbox_verdict': patch_report['pre_validation_verdict']
            },
            'governance_and_human_control': {
                'approval_status': human_approval_status,
                'executed_by': 'HUMAN_SOC_ANALYST' if human_approval_status == 'APPROVED' else 'REJECTED_BY_OPERATOR'
            },
            'regulatory_compliance_mapping': COMPLIANCE_MAP
        }

        self._append_to_log_file(audit_entry)
        return audit_entry

    def _append_to_log_file(self, entry: dict):
        """Appends JSON record to persistent log storage."""
        logs = []
        if os.path.exists(self.log_file):
            try:
                with open(self.log_file, 'r') as f:
                    logs = json.load(f)
            except Exception:
                logs = []

        logs.append(entry)

        with open(self.log_file, 'w') as f:
            json.dump(logs, f, indent=2)

if __name__ == '__main__':
    from src.red_team import RedTeamSimulator
    from src.blue_team import BlueTeamEnsemble
    from src.uncertainty_engine import EpistemicUncertaintyEngine
    from src.mitigation_engine import MitigationEngine

    # Test Complete Audit Pipeline Integration
    red_agent = RedTeamSimulator()
    blue_ensemble = BlueTeamEnsemble()
    uncertainty_engine = EpistemicUncertaintyEngine()
    mitigation_engine = MitigationEngine()
    logger = ComplianceAuditLogger()

    # 1. Simulate Attack
    attack = red_agent.generate_attack_payload('PRIVILEGE_ESCALATION')
    df_attack = red_agent.payload_to_dataframe(attack)

    # 2. ML Inference & Uncertainty Evaluation
    probs = blue_ensemble.predict_probabilities(df_attack)
    uncertainty_eval = uncertainty_engine.evaluate_uncertainty(probs)

    # 3. Patch & Twin Pre-Validation
    patch = mitigation_engine.generate_candidate_patch(attack['scenario_key'])
    patch_report = mitigation_engine.pre_validate_patch(attack, patch)

    # 4. Generate Compliance Log
    audit_record = logger.log_event(attack, uncertainty_eval, patch_report, human_approval_status='APPROVED')

    print("📜 Compliance & Audit Trail Entry Created:")
    print(f"🆔 Event ID  : {audit_record['event_id']}")
    print(f"⏱️ Timestamp : {audit_record['timestamp']}")
    print(f"🏛️ Compliance: NIS2 (Article 21) & IEC 62443 Mapped Successfully")
    print(f"📁 Log Location: {logger.log_file}")
    