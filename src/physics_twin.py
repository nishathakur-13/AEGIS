import numpy as np


# ---------------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------------
NOMINAL_FREQ_HZ        = 50.0          # European/Indian grid nominal
FREQ_TRIP_BAND_HZ      = 0.5           # ±0.5 Hz → under/over-frequency relay
VOLTAGE_BAND_WARN_PCT  = 5.0           # IEEE ±5% caution band
VOLTAGE_BAND_TRIP_PCT  = 10.0          # ±10% → breaker trips
XFMR_OVERLOAD_PCT      = 110.0         # transformer trips at 110% rating
XFMR_RATING_MVA        = 160.0         # nominal transformer rating


class PhysicsInformedDigitalTwin:
    """Physics-Informed Digital Twin (PIDT) Engine for Power Grid Operations.

    Enforces physical conservation laws (Kirchhoff's Laws, Power Flow Equations,
    frequency droop, and protection relay logic) to detect cyber-physical anomalies
    and evaluate mitigation safety.

    Models demonstrated:
      • Voltage deviation (per-unit bands + protection trip)
      • Current / overcurrent (thermal KCL proxy)
      • Active & Reactive power (3-phase S, P, Q, PF)
      • Power-flow imbalance (residual of S_measured vs √3·V·I)
      • Breaker status per node (over-voltage, over-current, relay logic)
      • Load redistribution (isolation forces adjacent lines to absorb shed load)
      • Frequency (ROCOF / droop model)
      • Line loading % and transformer loading %
    """

    def __init__(self,
                 base_voltage_kv: float = 138.0,
                 max_line_capacity_mw: float = 150.0,
                 nominal_freq_hz: float = NOMINAL_FREQ_HZ):
        self.base_voltage_kv       = base_voltage_kv
        self.max_line_capacity_mw  = max_line_capacity_mw
        self.nominal_freq_hz       = nominal_freq_hz
        # Rated current from line thermal capacity
        self._rated_current_a      = (max_line_capacity_mw * 1e3) / (np.sqrt(3) * base_voltage_kv)

    # ------------------------------------------------------------------
    # HELPER: per-unit voltage
    # ------------------------------------------------------------------
    def _pu_voltage(self, voltage_kv: float) -> float:
        return voltage_kv / self.base_voltage_kv

    # ------------------------------------------------------------------
    # 1. VERIFY PHYSICAL LAWS
    # ------------------------------------------------------------------
    def verify_physical_laws(self, telemetry: dict, scenario_key: str = None) -> dict:
        """Verifies incoming telemetry against fundamental electrical power laws.

        Checks
        ------
        1. Apparent Power Balance (Power-Flow Imbalance)
           S_measured = √(P² + Q²)  vs  S_calculated = √3·V·I / 1000
           Residual ≤ 8% → consistent.

        2. Voltage Deviation
           pu deviation from nominal.
           Band A (warning) : ±5%  (IEEE 1159)
           Band B (trip)    : ±10% → breaker trips automatically.

        3. KCL Proxy — Thermal Overcurrent
           I > 1.10 × I_rated → overcurrent flag.

        4. Power Factor & Reactive Power Ratio
           PF = P / S  (unity = purely resistive, low PF = reactive burden).
           Q/P ratio > 0.6 flagged as high-reactive-burden anomaly.

        5. Frequency Estimation (ROCOF proxy)
           Active power imbalance is used as a proxy for generation-load
           imbalance → estimates frequency deviation via droop constant.
           Δf = -D × (P_imbalance / S_base)   (D = 5 Hz/pu)

        6. Breaker Status
           Breaker trips if: overcurrent OR voltage outside ±10% band
           OR frequency outside nominal ± 0.5 Hz.

        7. Line / Transformer Loading
           Line loading   = (|S_measured| / max_line_capacity_mw) × 100 %
           Transformer loading = (|S_measured| / XFMR_RATING_MVA) × 100 %
        """
        voltage        = float(telemetry.get('voltage_kv',          self.base_voltage_kv))
        current        = float(telemetry.get('current_amps',         500.0))
        active_power   = float(telemetry.get('active_power_mw',     100.0))
        reactive_power = float(telemetry.get('reactive_power_mvar',  30.0))

        # ── 1. Apparent Power Balance ─────────────────────────────────
        s_measured   = float(np.sqrt(active_power**2 + reactive_power**2))   # MVA
        s_calculated = float((np.sqrt(3) * voltage * current) / 1e3)         # MVA from V·I
        power_residual_mva = float(np.abs(s_measured - s_calculated))
        power_residual_pct = float((power_residual_mva / max(s_calculated, 1e-5)) * 100.0)

        # ── 2. Voltage Deviation ──────────────────────────────────────
        pu_v             = self._pu_voltage(voltage)
        voltage_dev_pct  = float(np.abs(pu_v - 1.0) * 100.0)
        voltage_pu       = round(pu_v, 4)
        in_band_warn     = voltage_dev_pct <= VOLTAGE_BAND_WARN_PCT
        in_band_trip     = voltage_dev_pct <= VOLTAGE_BAND_TRIP_PCT
        voltage_band_tag = (
            "NORMAL"      if voltage_dev_pct <= VOLTAGE_BAND_WARN_PCT
            else "WARNING" if voltage_dev_pct <= VOLTAGE_BAND_TRIP_PCT
            else "CRITICAL"
        )

        # ── 3. KCL Proxy — Overcurrent ────────────────────────────────
        overcurrent_flag = bool(current > self._rated_current_a * 1.10)

        # ── 4. Power Factor & Reactive Power Ratio ────────────────────
        apparent_power_mva = s_measured
        power_factor       = float(active_power / max(apparent_power_mva, 1e-5))
        power_factor       = float(np.clip(power_factor, 0.0, 1.0))
        reactive_ratio     = float(reactive_power / max(active_power, 1e-5))
        high_reactive_flag = bool(reactive_ratio > 0.60)

        # ── 5. Frequency Estimation (droop-based) ─────────────────────
        #  Power imbalance fraction relative to rated capacity
        p_imbalance_pu = float((active_power - s_calculated) / max(self.max_line_capacity_mw, 1.0))
        D_droop        = 5.0    # Hz per pu  (typical primary droop constant)
        freq_deviation_hz = float(-D_droop * p_imbalance_pu)
        freq_deviation_hz = float(np.clip(freq_deviation_hz, -3.0, 3.0))
        freq_hz        = round(float(self.nominal_freq_hz + freq_deviation_hz), 3)
        freq_outside_band = bool(np.abs(freq_deviation_hz) > FREQ_TRIP_BAND_HZ)

        # ── 6. Breaker Status ─────────────────────────────────────────
        breaker_tripped = bool(
            overcurrent_flag
            or not in_band_trip          # voltage outside ±10%
            or freq_outside_band
        )
        breaker_cause = []
        if overcurrent_flag:             breaker_cause.append("OVERCURRENT")
        if not in_band_trip:             breaker_cause.append("VOLTAGE_OUT_OF_BAND")
        if freq_outside_band:            breaker_cause.append("FREQUENCY_DEVIATION")
        breaker_status = "OPEN (TRIPPED)" if breaker_tripped else "CLOSED (NORMAL)"

        # ── 7. Line & Transformer Loading ─────────────────────────────
        line_loading_pct       = float((s_measured / max(self.max_line_capacity_mw, 1.0)) * 100.0)
        transformer_loading_pct= float((s_measured / XFMR_RATING_MVA) * 100.0)
        transformer_overloaded = bool(transformer_loading_pct > XFMR_OVERLOAD_PCT)

        # ── Overall Physical Consistency ──────────────────────────────
        is_physically_consistent = (
            power_residual_pct  <= 8.0
            and voltage_dev_pct <= VOLTAGE_BAND_WARN_PCT
            and not overcurrent_flag
            and not high_reactive_flag
            and not freq_outside_band
        )

        return {
            # Core consistency flag
            "is_physically_consistent":     is_physically_consistent,
            "physical_anomaly_detected":    not is_physically_consistent,

            # Power-flow imbalance
            "power_residual_mva":           round(power_residual_mva, 3),
            "power_residual_pct":           round(power_residual_pct, 2),

            # Active / Reactive / Apparent power
            "active_power_mw":              round(active_power, 2),
            "reactive_power_mvar":          round(reactive_power, 2),
            "apparent_power_mva":           round(apparent_power_mva, 3),

            # Power factor
            "power_factor":                 round(power_factor, 4),
            "reactive_ratio":               round(reactive_ratio, 4),
            "high_reactive_flag":           high_reactive_flag,

            # Voltage
            "voltage_kv":                   round(voltage, 2),
            "voltage_pu":                   voltage_pu,
            "voltage_deviation_pct":        round(voltage_dev_pct, 2),
            "voltage_band":                 voltage_band_tag,

            # Current / overcurrent
            "current_amps":                 round(current, 1),
            "rated_current_amps":           round(self._rated_current_a, 1),
            "overcurrent_detected":         overcurrent_flag,

            # Frequency
            "frequency_hz":                 freq_hz,
            "frequency_deviation_hz":       round(freq_deviation_hz, 3),
            "frequency_outside_band":       freq_outside_band,

            # Breaker status
            "breaker_status":               breaker_status,
            "breaker_tripped":              breaker_tripped,
            "breaker_trip_causes":          breaker_cause,

            # Line & transformer loading
            "line_loading_pct":             round(line_loading_pct, 2),
            "transformer_loading_pct":      round(transformer_loading_pct, 2),
            "transformer_overloaded":       transformer_overloaded,
        }

    # ------------------------------------------------------------------
    # 2. SIMULATE MITIGATION SAFETY
    # ------------------------------------------------------------------
    def simulate_mitigation_safety(self,
                                   target_node: str,
                                   action_type: str,
                                   current_load_mw: float = 120.0,
                                   scenario_key: str = None) -> dict:
        """Simulates transmission-line stress and cascading failure risk when a
        candidate defense patch is deployed.

        Physics modelled
        ----------------
        Load redistribution
          FULL_NODE_ISOLATION / HARD_BLOCK:
            Shed load is redistributed across 3 adjacent lines (+35% factor).
            Per-line load = current_load_mw × 1.35 / 3 lines.
          DYNAMIC_MICRO_SEGMENTATION / RATE_LIMIT:
            Topology unchanged — no extra stress.

        Transformer loading
          Redistributed power flows through the substation transformer.
          Transformer loading % = redistributed_load / XFMR_RATING_MVA × 100.

        Frequency droop (post-event)
          ROCOF (Rate of Change of Frequency) estimated from load imbalance.
          Δf = -R × (ΔP / P_rated)    R = 0.05 pu/pu  (4% droop characteristic)
          f_post = 50.0 + Δf

        Breaker status per node
          Three representative nodes are modelled:
            - source_bus:   trips if transformer overloaded
            - load_bus:     trips if per-line stress > 110%
            - target_node:  trips if action is FULL_NODE_ISOLATION
        """
        n_lines            = 3          # adjacent lines absorbing the shed load

        if action_type in ("FULL_NODE_ISOLATION", "HARD_BLOCK"):
            redistributed_total_mw = current_load_mw * 1.35
            per_line_load_mw       = redistributed_total_mw / n_lines
            line_stress_pct        = float((redistributed_total_mw / self.max_line_capacity_mw) * 100.0)

            if line_stress_pct > 100.0:
                safety_verdict     = "REJECTED_PHYSICAL_OVERLOAD_RISK"
                cascading_risk_pct = round(line_stress_pct - 100.0, 2)
            else:
                safety_verdict     = "APPROVED_SAFE_ISOLATION"
                cascading_risk_pct = 0.0

            # Frequency droop from load loss
            delta_p_pu        = (current_load_mw * 0.35) / max(self.max_line_capacity_mw, 1.0)
            freq_delta_hz     = float(0.05 * delta_p_pu * self.nominal_freq_hz)   # slight rise after load shed
            freq_delta_hz     = round(float(np.clip(freq_delta_hz, -2.0, 2.0)), 3)

        elif action_type in ("DYNAMIC_MICRO_SEGMENTATION", "RATE_LIMIT"):
            redistributed_total_mw = current_load_mw
            per_line_load_mw       = current_load_mw / n_lines
            line_stress_pct        = float((current_load_mw / self.max_line_capacity_mw) * 100.0)
            safety_verdict         = "APPROVED_ZERO_DISRUPTION"
            cascading_risk_pct     = 0.0
            freq_delta_hz          = -0.01

        else:
            redistributed_total_mw = current_load_mw
            per_line_load_mw       = current_load_mw / n_lines
            line_stress_pct        = float((current_load_mw / self.max_line_capacity_mw) * 100.0)
            safety_verdict         = "APPROVED_NORMAL_OPERATIONS"
            cascading_risk_pct     = 0.0
            freq_delta_hz          = 0.0

        # ── Per-line load distribution ────────────────────────────────
        per_line_loading = {
            f"Line_{i+1}": round(float((per_line_load_mw / self.max_line_capacity_mw) * 100.0), 2)
            for i in range(n_lines)
        }

        # ── Transformer loading ───────────────────────────────────────
        transformer_loading_pct = float((redistributed_total_mw / XFMR_RATING_MVA) * 100.0)
        transformer_overloaded  = bool(transformer_loading_pct > XFMR_OVERLOAD_PCT)

        # ── Post-event frequency ──────────────────────────────────────
        freq_post_event_hz = round(float(self.nominal_freq_hz + freq_delta_hz), 3)
        freq_outside_band  = bool(np.abs(freq_delta_hz) > FREQ_TRIP_BAND_HZ)

        # ── Breaker statuses per node ─────────────────────────────────
        per_line_overloaded     = any(v > 100.0 for v in per_line_loading.values())
        breaker_statuses = {
            "source_bus":    "OPEN (TRIPPED)" if transformer_overloaded    else "CLOSED (NORMAL)",
            "load_bus":      "OPEN (TRIPPED)" if per_line_overloaded       else "CLOSED (NORMAL)",
            target_node:     "OPEN (ISOLATED)" if action_type in (
                                 "FULL_NODE_ISOLATION", "HARD_BLOCK")       else "CLOSED (NORMAL)",
        }

        return {
            "target_node":                  target_node,
            "action_evaluated":             action_type,

            # Line stress
            "line_stress_pct":              round(float(line_stress_pct), 2),
            "per_line_loading":             per_line_loading,
            "cascading_failure_risk_pct":   cascading_risk_pct,

            # Transformer
            "transformer_loading_pct":      round(float(transformer_loading_pct), 2),
            "transformer_overloaded":       transformer_overloaded,

            # Frequency
            "predicted_freq_delta_hz":      freq_delta_hz,
            "freq_post_event_hz":           freq_post_event_hz,
            "freq_outside_band":            freq_outside_band,

            # Breaker status per node
            "breaker_statuses":             breaker_statuses,

            # Load redistribution
            "redistributed_load_mw":        round(float(redistributed_total_mw), 2),
            "per_line_load_mw":             round(float(per_line_load_mw), 2),
            "n_lines_affected":             n_lines,

            # Verdict
            "physics_safety_verdict":       safety_verdict,
            "is_physically_safe":           safety_verdict.startswith("APPROVED"),
        }


# ---------------------------------------------------------------------------
# COMPONENT 3 — INTEGRATED SAFETY REPORT ENGINE
# ---------------------------------------------------------------------------
class IntegratedSafetyReportEngine:
    """Fuses the ML ensemble threat score with Physics Twin verdicts into a
    single Combined Risk Index (CRI) and issues one unified final safety verdict.

    Enhanced fusion formula (weighted):
        CRI = w_ml   × ml_threat_score
            + w_phy  × physics_anomaly_score
            + w_kcl  × overcurrent_score
            + w_freq × frequency_score
            + w_xfmr × transformer_score

    where:
        physics_anomaly_score = 0.55 × norm(power_residual_pct / 8.0)
                              + 0.30 × norm(voltage_deviation_pct / 5.0)
                              + 0.15 × high_reactive_flag
        overcurrent_score     = 1.0 if overcurrent else 0.0
        frequency_score       = min(|freq_dev| / 0.5, 1.0)     (normalised to trip band)
        transformer_score     = 1.0 if transformer overloaded else
                                min(transformer_loading_pct / 110.0, 1.0)

    Weights:
        w_ml   = 0.45
        w_phy  = 0.30
        w_kcl  = 0.10
        w_freq = 0.10
        w_xfmr = 0.05

    Final verdict tiers:
        CRI >= 0.80  →  CRITICAL_CONFIRMED
        CRI >= 0.55  →  HIGH_THREAT
        CRI >= 0.30  →  AMBIGUOUS_MONITOR
        CRI <  0.30  →  BENIGN_CLEAR
    """

    W_ML   = 0.45
    W_PHY  = 0.30
    W_KCL  = 0.10
    W_FREQ = 0.10
    W_XFMR = 0.05

    def generate_report(
        self,
        ml_eval:      dict,
        phys_verify:  dict,
        phys_safety:  dict,
        patch_report: dict,
    ) -> dict:

        # ── Input signals ────────────────────────────────────────────
        ml_score    = float(ml_eval.get("composite_threat_score", 0.0))
        ml_variance = float(ml_eval.get("epistemic_uncertainty_variance", 0.0))
        ml_decision = ml_eval.get("decision_verdict", "UNKNOWN")

        # Physics verify signals
        power_res_pct   = float(phys_verify.get("power_residual_pct",      0.0))
        volt_dev_pct    = float(phys_verify.get("voltage_deviation_pct",   0.0))
        overcurrent     = bool(phys_verify.get("overcurrent_detected",     False))
        phys_anomaly    = bool(phys_verify.get("physical_anomaly_detected", False))
        high_reactive   = bool(phys_verify.get("high_reactive_flag",       False))
        power_factor    = float(phys_verify.get("power_factor",            1.0))
        freq_dev_hz     = float(phys_verify.get("frequency_deviation_hz",  0.0))
        freq_hz         = float(phys_verify.get("frequency_hz",            NOMINAL_FREQ_HZ))
        breaker_tripped = bool(phys_verify.get("breaker_tripped",          False))
        xfmr_load_verify= float(phys_verify.get("transformer_loading_pct", 0.0))
        line_load_pct   = float(phys_verify.get("line_loading_pct",        0.0))
        voltage_band    = phys_verify.get("voltage_band", "NORMAL")

        # Physics safety signals
        line_stress    = float(phys_safety.get("line_stress_pct",           0.0))
        cascade_risk   = float(phys_safety.get("cascading_failure_risk_pct",0.0))
        phys_safe      = bool(phys_safety.get("is_physically_safe",         True))
        xfmr_load_safe = float(phys_safety.get("transformer_loading_pct",  0.0))
        xfmr_overloaded= bool(phys_safety.get("transformer_overloaded",    False))
        freq_post_evt  = float(phys_safety.get("freq_post_event_hz",       NOMINAL_FREQ_HZ))
        breaker_statuses = phys_safety.get("breaker_statuses",             {})

        # Patch signals
        sec_gain    = float(patch_report.get("security_gain_pct",    0.0))
        disruption  = float(patch_report.get("grid_disruption_pct",  0.0))

        # ── Normalised physics anomaly score (0–1) ────────────────────
        phy_score = float(np.clip(
            0.55 * min(power_res_pct / 8.0,   1.0)
          + 0.30 * min(volt_dev_pct  / 5.0,   1.0)
          + 0.15 * (1.0 if high_reactive else 0.0),
            0.0, 1.0
        ))

        kcl_score  = 1.0 if overcurrent else 0.0

        # Frequency deviation normalised to ±0.5 Hz trip band
        freq_score = float(min(abs(freq_dev_hz) / FREQ_TRIP_BAND_HZ, 1.0))

        # Transformer score: proportional loading towards 110% trip
        xfmr_score = float(
            1.0 if xfmr_overloaded
            else min(max(xfmr_load_safe, xfmr_load_verify) / XFMR_OVERLOAD_PCT, 1.0)
        )

        # ── Combined Risk Index ───────────────────────────────────────
        cri = float(
            self.W_ML   * ml_score
          + self.W_PHY  * phy_score
          + self.W_KCL  * kcl_score
          + self.W_FREQ * freq_score
          + self.W_XFMR * xfmr_score
        )
        cri = round(min(cri, 1.0), 4)

        # ── Confidence (penalise high ML uncertainty) ─────────────────
        confidence_pct = round((1.0 - min(ml_variance * 50, 0.40)) * 100, 1)

        # ── Final verdict ─────────────────────────────────────────────
        if cri >= 0.80:
            verdict           = "CRITICAL_CONFIRMED"
            verdict_color     = "critical"
            recommended_action = patch_report.get("action_description", "DYNAMIC_MICRO_SEGMENTATION")
            human_approval    = True
        elif cri >= 0.55:
            verdict           = "HIGH_THREAT"
            verdict_color     = "critical"
            recommended_action = patch_report.get("action_description", "RATE_LIMIT_AND_MONITOR")
            human_approval    = True
        elif cri >= 0.30:
            verdict           = "AMBIGUOUS_MONITOR"
            verdict_color     = "warning"
            recommended_action = "ESCALATE_TELEMETRY_LOGGING_AND_ALERT_SOC"
            human_approval    = False
        else:
            verdict           = "BENIGN_CLEAR"
            verdict_color     = "safe"
            recommended_action = "PASS_NORMAL_OPERATIONS"
            human_approval    = False

        # ── Physics safety gate ───────────────────────────────────────
        if not phys_safe and verdict in ("CRITICAL_CONFIRMED", "HIGH_THREAT"):
            recommended_action   = "DYNAMIC_MICRO_SEGMENTATION"
            physics_gate_triggered = True
        else:
            physics_gate_triggered = False

        return {
            # ── ML inputs ──
            "ml_threat_score":              round(ml_score, 4),
            "ml_decision":                  ml_decision,
            "ml_variance":                  round(ml_variance, 6),

            # ── Physics verify ──
            "physics_anomaly":              phys_anomaly,
            "power_residual_pct":           round(power_res_pct, 2),
            "voltage_deviation_pct":        round(volt_dev_pct, 2),
            "voltage_band":                 voltage_band,
            "active_power_mw":              round(float(phys_verify.get("active_power_mw", 0.0)), 2),
            "reactive_power_mvar":          round(float(phys_verify.get("reactive_power_mvar", 0.0)), 2),
            "apparent_power_mva":           round(float(phys_verify.get("apparent_power_mva", 0.0)), 3),
            "power_factor":                 round(power_factor, 4),
            "reactive_ratio":               round(float(phys_verify.get("reactive_ratio", 0.0)), 4),
            "high_reactive_flag":           high_reactive,
            "overcurrent_detected":         overcurrent,
            "frequency_hz":                 round(freq_hz, 3),
            "frequency_deviation_hz":       round(freq_dev_hz, 3),
            "frequency_outside_band":       bool(phys_verify.get("frequency_outside_band", False)),
            "breaker_tripped":              breaker_tripped,
            "breaker_trip_causes":          phys_verify.get("breaker_trip_causes", []),
            "line_loading_pct":             round(line_load_pct, 2),
            "transformer_loading_pct_live": round(xfmr_load_verify, 2),
            "transformer_overloaded_live":  bool(phys_verify.get("transformer_overloaded", False)),

            # ── Physics safety ──
            "line_stress_pct":              round(line_stress, 2),
            "cascading_failure_risk_pct":   round(cascade_risk, 2),
            "transformer_loading_pct":      round(xfmr_load_safe, 2),
            "transformer_overloaded":       xfmr_overloaded,
            "freq_post_event_hz":           round(freq_post_evt, 3),
            "breaker_statuses":             breaker_statuses,

            # ── Fusion outputs ──
            "physics_anomaly_score":        round(phy_score, 4),
            "frequency_score":              round(freq_score, 4),
            "transformer_score":            round(xfmr_score, 4),
            "combined_risk_index":          cri,
            "confidence_pct":               confidence_pct,

            # ── Final verdict ──
            "final_verdict":                verdict,
            "verdict_color":                verdict_color,
            "recommended_action":           recommended_action,
            "physics_gate_triggered":       physics_gate_triggered,
            "human_approval_required":      human_approval,

            # ── Patch summary ──
            "security_gain_pct":            round(sec_gain, 1),
            "grid_disruption_pct":          round(disruption, 1),
        }
