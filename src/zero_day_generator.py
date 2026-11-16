import os
import sys

import torch
import torch.nn as nn
import numpy as np

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import ACTIVE_DATASET


class TabularDiffusionBlock(nn.Module):
    """Deep Denoising Neural Network for Tabular Physical Data Diffusion."""

    def __init__(self, feature_dim: int = 4, condition_dim: int = 1):
        super().__init__()
        # Inputs: noisy feature vector + condition + time step embedding
        input_dim = feature_dim + condition_dim + 1
        self.net = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.ReLU(),
            nn.Linear(64, 64),
            nn.ReLU(),
            nn.Linear(64, feature_dim),
        )

    def forward(self, x_t: torch.Tensor, c: torch.Tensor, t: torch.Tensor) -> torch.Tensor:
        # Concatenate noisy state, scenario condition, and time step
        t_normalized = t.float().unsqueeze(1) / 1000.0
        inputs = torch.cat([x_t, c, t_normalized], dim=-1)
        return self.net(inputs)


class ConditionalDiffusionGenerator:
    """Diffusion-based Generator for Synthetic Zero-Day Cyber-Physical Attack Payloads."""

    def __init__(self, feature_dim: int = 4, timesteps: int = 100):
        self.feature_dim = feature_dim
        self.timesteps = timesteps
        self.dataset_mode = ACTIVE_DATASET
        self.model = TabularDiffusionBlock(feature_dim=feature_dim, condition_dim=1)
        self.model.eval()  # Inference mode for runtime generation

        # Linear noise schedule constants
        self.beta = torch.linspace(1e-4, 0.02, timesteps)
        self.alpha = 1.0 - self.beta
        self.alpha_hat = torch.cumprod(self.alpha, dim=0)

    def _build_batadal_features(self, scenario_condition: float,
                                 voltage_kv: float, current_amps: float,
                                 active_power_mw: float) -> dict:
        """
        Derive a plausible 59-column BATADAL ICS sensor reading from the
        physics-layer telemetry produced by the diffusion model.

        Higher scenario_condition (closer to 1.0) = more aggressive anomaly,
        so pump flows drop, statuses become contradictory, tanks drain, and
        pressures spike — mirroring real BATADAL attack patterns.
        """
        rng = np.random.default_rng()

        # ── Attack severity scaling ────────────────────────────────────
        # s=0 → benign; s=1 → critical attack
        s = float(np.clip(scenario_condition, 0.0, 1.0))

        # ── Tank levels: drain under attack ───────────────────────────
        base_levels = [1.4, 1.3, 1.5, 1.2, 1.6, 1.1, 1.7]
        tank_levels = {
            f'L_T{i}': round(max(0.05, float(rng.normal(lv * (1 - 0.55 * s), 0.04))), 4)
            for i, lv in enumerate(base_levels, 1)
        }

        # ── Pump flows: disrupted under attack ─────────────────────────
        nominal_flows = {'F_PU1': 1.8, 'F_PU2': 2.1, 'F_PU4': 1.5,
                         'F_PU6': 2.0, 'F_PU7': 1.7, 'F_PU8': 1.9,
                         'F_PU10': 1.6, 'F_PU11': 2.2}
        pump_flows = {k: round(max(0.0, float(rng.normal(v * (1 - 0.8 * s), 0.2))), 4)
                      for k, v in nominal_flows.items()}

        # ── Pump statuses: contradictory (on but no flow) under FDIA ──
        # High severity → pumps report ON while flows are near-zero
        pu_status_keys = ['S_PU1', 'S_PU2', 'S_PU4', 'S_PU6', 'S_PU7', 'S_PU8', 'S_PU10', 'S_PU11']
        if s > 0.6:
            pump_status = {k: 1 for k in pu_status_keys}   # all "on" — physics lie
        else:
            pump_status = {k: int(rng.choice([0, 1], p=[0.2, 0.8])) for k in pu_status_keys}

        # ── Valve ─────────────────────────────────────────────────────
        f_v2 = round(max(0.0, float(rng.normal(1.2 * (1 - 0.6 * s), 0.1))), 4)
        s_v2 = 1

        # ── Junction pressures: spike under attack ─────────────────────
        nominal_p = {'P_J280': 55, 'P_J269': 58, 'P_J300': 52, 'P_J256': 60,
                     'P_J289': 54, 'P_J415': 57, 'P_J302': 53, 'P_J306': 56,
                     'P_J307': 59, 'P_J317': 61, 'P_J14': 50,  'P_J422': 63}
        pressures = {k: round(float(rng.normal(v * (1 + 0.5 * s), 1.5)), 4)
                     for k, v in nominal_p.items()}

        raw = {**tank_levels, **pump_flows, **pump_status,
               'F_V2': f_v2, 'S_V2': s_v2, **pressures}

        # ── Engineered aggregate features ──────────────────────────────
        tv   = list(tank_levels.values())
        pfv  = list(pump_flows.values())
        psv  = [pump_status[f'S_PU{i}'] for i in [1, 2, 4, 6, 7, 8, 10, 11]]
        pv   = list(pressures.values())
        ac   = max(1, sum(psv))
        tf   = sum(pfv)

        def _delta(v):    return round(abs(float(rng.normal(v * 0.05 + 0.001, 0.002))), 5)
        def _roll_std(v): return round(abs(float(rng.normal(v * 0.03 + 0.001, 0.001))), 5)

        raw.update({
            'mean_tank_level':    round(float(np.mean(tv)), 5),
            'tank_level_std':     round(float(np.std(tv)),  5),
            'min_tank_level':     round(float(np.min(tv)),  5),
            'total_pump_flow':    round(tf, 5),
            'active_pump_count':  ac,
            'mean_pressure':      round(float(np.mean(pv)), 5),
            'pressure_std':       round(float(np.std(pv)),  5),
            'pressure_range':     round(float(np.max(pv) - np.min(pv)), 5),
            'flow_per_pump':      round(tf / ac, 5),
            'pu6_flow_x_status':  round(raw['F_PU6'] * raw['S_PU6'], 5),
            'pu11_flow_x_status': round(raw['F_PU11'] * raw['S_PU11'], 5),
            'pu7_inactive_flow':  round(raw['F_PU7'] * (1 - raw['S_PU7']), 5),
            'F_PU6_delta':        _delta(raw['F_PU6']),
            'F_PU6_rolling_std':  _roll_std(raw['F_PU6']),
            'F_PU7_delta':        _delta(raw['F_PU7']),
            'F_PU7_rolling_std':  _roll_std(raw['F_PU7']),
            'F_PU11_delta':       _delta(raw['F_PU11']),
            'F_PU11_rolling_std': _roll_std(raw['F_PU11']),
            'L_T1_delta':         _delta(raw['L_T1']),
            'L_T1_rolling_std':   _roll_std(raw['L_T1']),
            'L_T7_delta':         _delta(raw['L_T7']),
            'L_T7_rolling_std':   _roll_std(raw['L_T7']),
        })
        return raw

    def generate_zero_day_payload(self, scenario_condition: float = 1.0) -> dict:
        """Runs Reverse Diffusion Process: Noise -> Synthetic Physical Telemetry."""
        with torch.no_grad():
            # 1. Start with pure Gaussian Noise (Prior Distribution)
            x_t = torch.randn((1, self.feature_dim))
            condition = torch.tensor([[scenario_condition]], dtype=torch.float32)

            # 2. Iterative Denoising Steps (Reverse Process)
            for step in reversed(range(0, self.timesteps)):
                t = torch.tensor([step])
                predicted_noise = self.model(x_t, condition, t)
                
                alpha_t = self.alpha[step]
                alpha_hat_t = self.alpha_hat[step]
                beta_t = self.beta[step]

                if step > 0:
                    noise = torch.randn_like(x_t)
                else:
                    noise = 0

                # Denoising update step
                x_t = (1 / torch.sqrt(alpha_t)) * (
                    x_t - ((1 - alpha_t) / torch.sqrt(1 - alpha_hat_t)) * predicted_noise
                ) + torch.sqrt(beta_t) * noise

            # 3. Denormalize generated features into realistic SCADA telemetry scale
            generated_vector = x_t.squeeze(0).numpy()
            
            # Feature mapping with intentional physics-violating perturbations (Zero-Day FDIA)
            voltage_kv = float(np.clip(138.0 + generated_vector[0] * 12.0, 110.0, 160.0))
            current_amps = float(np.clip(500.0 + generated_vector[1] * 200.0, 200.0, 900.0))
            active_power_mw = float(np.clip(300.0 + generated_vector[2] * 80.0, 50.0, 450.0))
            reactive_power_mvar = float(np.clip(45.0 + generated_vector[3] * 15.0, 10.0, 90.0))

        return {
            "scenario_key": "SYNTHETIC_DIFFUSION_ZERO_DAY",
            "mitre_id": "SCEN-04-DIFFUSION",
            "attack_name": "GenAI Diffusion Synthetic Zero-Day (FDIA Vector)",
            "target_node": "Transformer_Substation_04",
            "severity": "CRITICAL",
            "voltage_kv": round(voltage_kv, 2),
            "current_amps": round(current_amps, 2),
            "active_power_mw": round(active_power_mw, 2),
            "reactive_power_mvar": round(reactive_power_mvar, 2),
            "phys_telemetry": {
                "voltage_kv": round(voltage_kv, 2),
                "current_amps": round(current_amps, 2),
                "active_power_mw": round(active_power_mw, 2),
                "reactive_power_mvar": round(reactive_power_mvar, 2),
            },
            "network_features": {
                "flow_duration": round(float(np.random.uniform(350.0, 600.0)), 2),
                "total_fwd_packets": int(np.random.randint(500, 1200)),
                "total_bwd_packets": int(np.random.randint(100, 400)),
                "packet_length_mean": round(float(np.random.uniform(1100.0, 1600.0)), 2),
                "unauthorized_port_access": 1,
                "failed_login_attempts": int(np.random.randint(0, 5)),
                "privilege_escalation_flag": 1,
                "api_response_time_ms": round(float(np.random.uniform(150.0, 450.0)), 2)
            },
            "batadal_features": self._build_batadal_features(
                scenario_condition, voltage_kv, current_amps, active_power_mw
            ),
        }