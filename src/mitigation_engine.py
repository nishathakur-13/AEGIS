import os
import sys

# Ensure root directory is in Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import ATTACK_SCENARIOS
from src.digital_twin import DigitalTwinSandbox

class MitigationEngine:
    """
    Formulates candidate mitigation policies and orchestrates
    pre-validation inside the Ephemeral Digital Twin Sandbox.
    """
    def __init__(self):
        self.sandbox = DigitalTwinSandbox()

    def generate_candidate_patch(self, scenario_key: str) -> dict:
        """
        Generates structured defense policy based on scenario signature.
        """
        scenario = ATTACK_SCENARIOS.get(scenario_key, {
            'mitigation': 'Apply Default Dynamic Firewall Restriction & Token Revocation',
            'target': 'SCADA_Node_Generic'
        })

        patch_config = {
            'patch_id': f"PATCH_{scenario_key}_2026_01",
            'scenario_key': scenario_key,
            'target_node': scenario['target'],
            'action_description': scenario['mitigation'],
            'policy_rules': [
                "REJECT TCP Flow from unverified src_ip",
                "ISOLATE_PORT 8080/tcp",
                "FORCE_PKI_REAUTH"
            ]
        }
        return patch_config

    def pre_validate_patch(self, attack_payload: dict, patch_config: dict) -> dict:
        """
        Executes pre-validation inside Digital Twin to ensure Zero Grid Disruption.
        """
        target_node = attack_payload['target_node']
        
        # 1. Spin up sandbox
        self.sandbox.spin_up_sandbox(target_node)
        
        # 2. Execute safe attack inside sandbox
        self.sandbox.execute_safe_attack(attack_payload)
        
        # 3. Apply and test candidate patch
        validation_result = self.sandbox.validate_defense_patch(patch_config)
        
        # 4. Terminate sandbox
        self.sandbox.terminate_sandbox()

        return {
            'patch_id': patch_config['patch_id'],
            'target_node': target_node,
            'action_description': patch_config['action_description'],
            'policy_rules': patch_config['policy_rules'],
            'pre_validation_verdict': validation_result['sandbox_verdict'],
            'security_gain_pct': validation_result['security_gain_percentage'],
            'grid_disruption_pct': validation_result['operational_disruption_percentage'],
            'requires_human_approval': True
        }

if __name__ == '__main__':
    from src.red_team import RedTeamSimulator

    red_agent = RedTeamSimulator()
    mitigation_engine = MitigationEngine()

    attack = red_agent.generate_attack_payload('LATERAL_MOVEMENT')
    patch = mitigation_engine.generate_candidate_patch(attack['scenario_key'])

    print("🛡️ Candidate Defense Policy Formulated:")
    print(f"📌 Patch ID : {patch['patch_id']}")
    print(f"🎯 Action   : {patch['action_description']}")

    print("\n📦 Pre-validating in Digital Twin Sandbox...")
    val_report = mitigation_engine.pre_validate_patch(attack, patch)

    print("\n✅ Digital Twin Validation Report:")
    print(f"🔒 Security Gain    : {val_report['security_gain_pct']}%")
    print(f"⚡ Disruption Risk  : {val_report['grid_disruption_pct']}%")
    print(f"⚖️ Final Verdict     : {val_report['pre_validation_verdict']}")