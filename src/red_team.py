import os
import sys
import time
import numpy as np
import pandas as pd

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import ATTACK_SCENARIOS, ACTIVE_DATASET, BATADAL_FEATURE_COLUMNS


# ---------------------------------------------------------------------------
# ASSET INVENTORY — one realistic profile per node type
# ---------------------------------------------------------------------------

ASSET_INVENTORY = {
    "SCADA_Gateway_01": {
        "os": "Windows Server 2012 R2",
        "firmware": "Siemens S7-300 v3.2.1",
        "open_ports": [102, 502, 3389, 8080, 22],          # Modbus, S7comm, RDP, HTTP, SSH
        "services": {
            102:  "ISO-TSAP / S7comm",
            502:  "Modbus/TCP",
            3389: "RDP (Remote Desktop Protocol)",
            8080: "HTTP management console",
            22:   "OpenSSH 7.4",
        },
        "cves": [
            {
                "id": "CVE-2019-13945",
                "cvss": 9.8,
                "description": "Siemens S7-1500: unauthenticated remote code execution via S7comm-plus",
                "affected": "S7comm port 102",
                "exploitable": True,
            },
            {
                "id": "CVE-2019-0708",
                "cvss": 9.8,
                "description": "BlueKeep: RDP pre-auth RCE on Windows Server 2012 R2 (unpatched)",
                "affected": "RDP port 3389",
                "exploitable": True,
            },
            {
                "id": "CVE-2021-34527",
                "cvss": 8.8,
                "description": "PrintNightmare: privilege escalation via Windows Print Spooler",
                "affected": "Windows Server 2012 R2",
                "exploitable": True,
            },
        ],
        "misconfigurations": [
            "Modbus/TCP port 502 exposed with no authentication (ICS default)",
            "HTTP management console on port 8080 — no TLS, default credentials active",
            "RDP enabled and internet-facing (NIS2 Article 21 violation)",
            "Firewall rule allows ANY:ANY inbound on port 102 from engineering VLAN",
        ],
        "weak_credentials": [
            {"service": "HTTP console (port 8080)", "username": "admin",    "password": "admin"},
            {"service": "RDP (port 3389)",           "username": "scada_op", "password": "Siemens1"},
            {"service": "SSH (port 22)",              "username": "root",     "password": "root123"},
        ],
    },

    "Energy_EMS_DB": {
        "os": "Red Hat Enterprise Linux 7.6",
        "firmware": "OSIsoft PI Server 2018 SP3",
        "open_ports": [5450, 5468, 3306, 1433, 5432],       # PI, PI AF, MySQL, MSSQL, PostgreSQL
        "services": {
            5450: "OSIsoft PI Data Archive",
            5468: "OSIsoft PI Asset Framework",
            3306: "MySQL 5.7.32 (unencrypted)",
            1433: "Microsoft SQL Server 2016",
            5432: "PostgreSQL 9.6",
        },
        "cves": [
            {
                "id": "CVE-2021-44228",
                "cvss": 10.0,
                "description": "Log4Shell: JNDI injection RCE in OSIsoft PI Server logging component",
                "affected": "PI Server 2018 SP3 (Log4j 2.14)",
                "exploitable": True,
            },
            {
                "id": "CVE-2020-1472",
                "cvss": 10.0,
                "description": "Zerologon: unauthenticated domain privilege escalation via Netlogon",
                "affected": "Domain controller authentication",
                "exploitable": True,
            },
            {
                "id": "CVE-2019-2725",
                "cvss": 9.8,
                "description": "Oracle WebLogic deserialization RCE — PI web API component",
                "affected": "PI Web API 2018",
                "exploitable": False,
            },
        ],
        "misconfigurations": [
            "MySQL on port 3306 accepting remote connections with no TLS",
            "PI Data Archive allows anonymous read of all historical sensor data",
            "PostgreSQL pg_hba.conf set to 'trust' for local subnet — no password auth",
            "Service account 'pi_service' has local administrator privileges (over-permissioned)",
        ],
        "weak_credentials": [
            {"service": "MySQL (port 3306)",       "username": "root",       "password": ""},
            {"service": "PI Data Archive",         "username": "piadmin",    "password": "piadmin"},
            {"service": "PostgreSQL (port 5432)",  "username": "postgres",   "password": "postgres"},
        ],
    },

    "Substation_API_03": {
        "os": "VxWorks 6.9 (embedded RTOS)",
        "firmware": "ABB REX640 IED firmware v1.1.3",
        "open_ports": [80, 443, 161, 102, 4840],             # HTTP, HTTPS, SNMP, S7, OPC-UA
        "services": {
            80:   "HTTP — ABB web interface (unencrypted)",
            443:  "HTTPS — self-signed certificate (expired 2022)",
            161:  "SNMPv1 community string: 'public'",
            102:  "IEC 61850 / S7comm",
            4840: "OPC-UA (no authentication configured)",
        },
        "cves": [
            {
                "id": "CVE-2022-34151",
                "cvss": 9.1,
                "description": "ABB REX640: authentication bypass via crafted HTTP request to /api/v1/config",
                "affected": "ABB REX640 firmware < 1.2.0",
                "exploitable": True,
            },
            {
                "id": "CVE-2018-19615",
                "cvss": 9.8,
                "description": "Rockwell/Allen-Bradley: PCCC command injection via EtherNet/IP",
                "affected": "EtherNet/IP stack on IED",
                "exploitable": False,
            },
            {
                "id": "CVE-2023-28489",
                "cvss": 9.4,
                "description": "Siemens SINEMA Remote Connect: SSRF to internal OT network",
                "affected": "OPC-UA server (port 4840)",
                "exploitable": True,
            },
        ],
        "misconfigurations": [
            "SNMPv1 with community string 'public' — exposes full device MIB unauthenticated",
            "OPC-UA endpoint on port 4840 with Anonymous authentication policy enabled",
            "HTTPS certificate expired January 2022 — TLS verification disabled on all clients",
            "IEC 61850 GOOSE multicast not MAC-filtered — any LAN host can inject GOOSE frames",
        ],
        "weak_credentials": [
            {"service": "HTTP web interface (port 80)",  "username": "Admin",  "password": "Admin"},
            {"service": "SNMP (port 161)",               "username": "N/A",    "password": "public"},
            {"service": "OPC-UA (port 4840)",            "username": "guest",  "password": ""},
        ],
    },

    "Transformer_Substation_04": {
        "os": "Windows Embedded Standard 7",
        "firmware": "GE Grid Solutions UR Series v7.41",
        "open_ports": [102, 20000, 2404, 8080, 445],         # S7, DNP3, IEC-104, HTTP, SMB
        "services": {
            102:   "S7comm / IEC 61850",
            20000: "DNP3 over TCP (unauthenticated)",
            2404:  "IEC 60870-5-104 (no authentication)",
            8080:  "GE UR web interface",
            445:   "SMB (Windows file sharing — EternalBlue exposed)",
        },
        "cves": [
            {
                "id": "CVE-2017-0144",
                "cvss": 9.3,
                "description": "EternalBlue: SMBv1 RCE on Windows Embedded Standard 7 (unpatched)",
                "affected": "SMB port 445",
                "exploitable": True,
            },
            {
                "id": "CVE-2021-34523",
                "cvss": 9.0,
                "description": "ProxyShell: Exchange SSRF + privilege escalation chain",
                "affected": "Windows Embedded / exchange integration",
                "exploitable": False,
            },
            {
                "id": "CVE-2022-26857",
                "cvss": 8.8,
                "description": "GE Grid Solutions UR: buffer overflow via crafted DNP3 packet",
                "affected": "GE UR firmware v7.41 — DNP3 port 20000",
                "exploitable": True,
            },
        ],
        "misconfigurations": [
            "DNP3 on port 20000 with no authentication (DNP3 SA not enabled — ICS default)",
            "IEC 60870-5-104 ASDU address 1 responds to unauthenticated control commands",
            "SMBv1 enabled — EternalBlue directly exploitable",
            "GE UR web interface accessible from corporate IT VLAN (no OT/IT segmentation)",
        ],
        "weak_credentials": [
            {"service": "GE UR web interface (port 8080)", "username": "admin",  "password": "admin"},
            {"service": "DNP3 (port 20000)",               "username": "N/A",    "password": "N/A (no auth)"},
            {"service": "SMB (port 445)",                  "username": "GEAdmin","password": "GEAdmin1"},
        ],
    },

    # Fallback generic node
    "Substation_Telemetry_01": {
        "os": "Linux (embedded)",
        "firmware": "Generic RTU firmware v2.1",
        "open_ports": [502, 80, 22],
        "services": {502: "Modbus/TCP", 80: "HTTP telemetry dashboard", 22: "SSH"},
        "cves": [],
        "misconfigurations": [
            "Modbus/TCP port 502 unauthenticated — ICS default",
            "HTTP dashboard on port 80 — no TLS",
        ],
        "weak_credentials": [
            {"service": "SSH (port 22)", "username": "admin", "password": "admin"},
        ],
    },
}

# Maps discovered finding type + node → most appropriate attack scenario
_VULN_TO_SCENARIO = {
    ("CVE",  "SCADA_Gateway_01"):         "LATERAL_MOVEMENT",
    ("CRED", "SCADA_Gateway_01"):         "LATERAL_MOVEMENT",
    ("CVE",  "Energy_EMS_DB"):            "PRIVILEGE_ESCALATION",
    ("CRED", "Energy_EMS_DB"):            "PRIVILEGE_ESCALATION",
    ("CVE",  "Substation_API_03"):        "TELEMETRY_SPOOFING",
    ("MISC", "Substation_API_03"):        "TELEMETRY_SPOOFING",
    ("CVE",  "Transformer_Substation_04"):"FDIA_PHYSICS_FAILURE",
    ("MISC", "Transformer_Substation_04"):"FDIA_PHYSICS_FAILURE",
}


# ---------------------------------------------------------------------------
# VULNERABILITY SCANNER
# ---------------------------------------------------------------------------

class VulnerabilityScanner:
    """Simulated Red Team vulnerability scanner.

    Models the reconnaissance + discovery phase of a real penetration test:
      1. Port scan      — enumerate open services
      2. CVE match      — check service versions against known CVE database
      3. Credential audit — test default / weak credentials
      4. Misconfiguration audit — check for known ICS/OT misconfigs

    Returns a structured VulnReport dict that the RedTeamSimulator uses to
    select which attack scenario is most realistic for this target.

    The asset inventory (ASSET_INVENTORY above) is the simulated "truth" of
    what a real scanner would discover. Values are representative of real
    vulnerabilities found in OT environments (Dragos, CISA ICS advisories,
    Claroty research).
    """

    def scan(self, target_node: str, seed: int = None) -> dict:
        """Run a full simulated vulnerability assessment against target_node.

        Returns
        -------
        vuln_report : dict with keys:
            target_node, scan_timestamp, open_ports, exploitable_cves,
            weak_credentials, misconfigurations, highest_cvss, risk_rating,
            recommended_attack_vector, findings_summary
        """
        if seed is not None:
            np.random.seed(seed)

        asset = ASSET_INVENTORY.get(target_node, ASSET_INVENTORY["Substation_Telemetry_01"])

        # ── 1. Port scan (simulate scan noise — occasionally miss one port) ──
        detected_ports = [
            p for p in asset["open_ports"]
            if np.random.random() > 0.05          # 5% chance of evasion per port
        ]
        detected_services = {p: asset["services"][p] for p in detected_ports if p in asset["services"]}

        # ── 2. CVE matching ───────────────────────────────────────────────────
        exploitable_cves = [
            cve for cve in asset["cves"]
            if cve["exploitable"]
            and np.random.random() > 0.10          # 10% false-negative (patched by ops)
        ]

        # ── 3. Credential audit ───────────────────────────────────────────────
        found_weak_creds = [
            cred for cred in asset["weak_credentials"]
            if np.random.random() > 0.15           # 15% chance cred was rotated
        ]

        # ── 4. Misconfiguration audit ─────────────────────────────────────────
        found_misconfigs = [
            m for m in asset["misconfigurations"]
            if np.random.random() > 0.10           # 10% chance already fixed
        ]

        # ── Risk rating ───────────────────────────────────────────────────────
        max_cvss = max((c["cvss"] for c in exploitable_cves), default=0.0)
        n_creds  = len(found_weak_creds)
        n_misc   = len(found_misconfigs)

        if max_cvss >= 9.0 or n_creds >= 2:
            risk_rating = "CRITICAL"
        elif max_cvss >= 7.0 or n_creds >= 1:
            risk_rating = "HIGH"
        elif max_cvss >= 4.0 or n_misc >= 2:
            risk_rating = "MEDIUM"
        else:
            risk_rating = "LOW"

        # ── Select most realistic attack vector based on findings ─────────────
        recommended_vector = self._recommend_attack_vector(
            target_node, exploitable_cves, found_weak_creds, found_misconfigs
        )

        # ── Human-readable findings summary ──────────────────────────────────
        findings_summary = self._build_summary(
            exploitable_cves, found_weak_creds, found_misconfigs
        )

        return {
            "target_node":              target_node,
            "asset_os":                 asset["os"],
            "asset_firmware":           asset["firmware"],
            "scan_timestamp":           time.strftime("%Y-%m-%dT%H:%M:%S"),
            "open_ports_detected":      detected_ports,
            "detected_services":        detected_services,
            "exploitable_cves":         exploitable_cves,
            "weak_credentials_found":   found_weak_creds,
            "misconfigurations_found":  found_misconfigs,
            "highest_cvss":             round(max_cvss, 1),
            "weak_credential_count":    n_creds,
            "misconfiguration_count":   n_misc,
            "risk_rating":              risk_rating,
            "recommended_attack_vector": recommended_vector,
            "findings_summary":         findings_summary,
        }

    def _recommend_attack_vector(
        self,
        target_node: str,
        cves: list,
        creds: list,
        misconfigs: list,
    ) -> str:
        """Select the most credible attack vector from discovered findings."""
        # Highest-CVSS exploitable CVE wins if CVSS ≥ 9.0
        if cves:
            top_cve = max(cves, key=lambda c: c["cvss"])
            if top_cve["cvss"] >= 9.0:
                return (
                    f"Exploit {top_cve['id']} (CVSS {top_cve['cvss']}) "
                    f"via {top_cve['affected']}"
                )

        # Default credentials are highly reliable attack paths
        if creds:
            top_cred = creds[0]
            return (
                f"Authenticate with default credential "
                f"'{top_cred['username']}'/'{top_cred['password']}' "
                f"on {top_cred['service']}"
            )

        # Unauthenticated protocol exposure
        if misconfigs:
            return f"Exploit misconfiguration: {misconfigs[0]}"

        return "No high-confidence attack vector found — low-risk target"

    def _build_summary(self, cves, creds, misconfigs) -> list[str]:
        lines = []
        for c in cves:
            lines.append(
                f"[CVE {c['id']} · CVSS {c['cvss']}] {c['description']}"
            )
        for cr in creds:
            lines.append(
                f"[WEAK CRED] {cr['service']}: "
                f"'{cr['username']}' / '{cr['password']}'"
            )
        for m in misconfigs:
            lines.append(f"[MISCONFIG] {m}")
        return lines


# ---------------------------------------------------------------------------
# RED TEAM SIMULATOR
# ---------------------------------------------------------------------------

class RedTeamSimulator:
    """Purple Team Red Team Agent.

    Implements a genuine two-phase attack lifecycle:

    Phase 1 — RECONNAISSANCE & VULNERABILITY DISCOVERY
        VulnerabilityScanner probes the target node's simulated asset
        inventory: open ports, exploitable CVEs, weak/default credentials,
        and OT/ICS misconfigurations. Mirrors what a real penetration tester
        or attacker would discover using tools like Nmap, Shodan, Metasploit,
        and Claroty's asset discovery engine.

    Phase 2 — EXPLOITATION & PAYLOAD GENERATION
        The scanner's findings drive attack vector selection:
        - Exploitable CVE (CVSS ≥ 9.0) on RDP/S7comm/SMB → Lateral Movement
        - Default credential on EMS/DB → Privilege Escalation
        - Unauthenticated OPC-UA / Modbus → Telemetry Spoofing
        - DNP3 / IEC-104 without auth + EternalBlue → FDIA + Physics Failure

        Statistically realistic telemetry is then generated *for that specific
        attack vector*, with Gaussian/Poisson/exponential noise injected to
        produce overlapping feature distributions.

    Every generated payload carries the full vuln_report from Phase 1,
    so the Blue Team, Physics Twin, and HITL gate all have provenance:
    not just "what happened" but "how the attacker got in."
    """

    def __init__(self):
        self.dataset_mode = ACTIVE_DATASET
        self.scanner      = VulnerabilityScanner()
        self.feature_names = [
            'flow_duration', 'total_fwd_packets', 'total_bwd_packets',
            'packet_length_mean', 'failed_login_attempts',
            'privilege_escalation_flag', 'api_response_time_ms',
            'unauthorized_port_access',
        ]

    # ------------------------------------------------------------------
    # PUBLIC API
    # ------------------------------------------------------------------

    def scan_target(self, target_node: str) -> dict:
        """Run Phase 1 standalone — returns vuln_report for display."""
        return self.scanner.scan(target_node)

    def generate_attack_payload(self, scenario_key: str = 'LATERAL_MOVEMENT') -> dict:
        """Phase 1 + Phase 2: scan → select vector → generate telemetry payload."""
        scenario = ATTACK_SCENARIOS.get(scenario_key, ATTACK_SCENARIOS['BENIGN_TRAFFIC'])
        target   = scenario['target']

        # ── Phase 1: Vulnerability Discovery ─────────────────────────────
        if scenario_key == 'BENIGN_TRAFFIC':
            vuln_report = None                     # No scan for benign baseline
        else:
            vuln_report = self.scanner.scan(target)
            # If scanner finds findings that suggest a different scenario,
            # allow the scenario to be overridden by what was actually found
            scenario_key = self._resolve_scenario(scenario_key, target, vuln_report)
            scenario     = ATTACK_SCENARIOS.get(scenario_key, scenario)

        # ── Phase 2: Payload Generation ───────────────────────────────────
        if self.dataset_mode == 'batadal':
            payload = self._generate_batadal_payload(scenario_key, scenario)
        else:
            payload = self._generate_synthetic_payload(scenario_key, scenario)

        if vuln_report is not None:
            payload['vuln_report'] = vuln_report

        return payload

    def payload_to_dataframe(self, payload: dict) -> pd.DataFrame:
        if self.dataset_mode == 'batadal':
            df = pd.DataFrame([payload['features']])
            return df[BATADAL_FEATURE_COLUMNS]
        df = pd.DataFrame([payload['features']])
        return df[self.feature_names]

    # ------------------------------------------------------------------
    # SCENARIO RESOLUTION — finding-driven override
    # ------------------------------------------------------------------

    def _resolve_scenario(
        self, requested: str, target: str, vuln_report: dict
    ) -> str:
        """Map discovered findings to the most credible attack scenario.

        If the user selected a scenario manually, honour it — the scan
        provides the *justification* for how that attack would be executed.
        Only override if scan finds something more severe than the requested
        scenario, or if the requested scenario is inconsistent with findings.
        """
        # Benign override: if scan finds nothing, downgrade to BENIGN
        if (
            not vuln_report["exploitable_cves"]
            and not vuln_report["weak_credentials_found"]
            and not vuln_report["misconfigurations_found"]
        ):
            return "BENIGN_TRAFFIC"

        # Check if node-specific finding suggests a more precise scenario
        for (finding_type, node), mapped_scenario in _VULN_TO_SCENARIO.items():
            if node in target:
                if finding_type == "CVE" and vuln_report["exploitable_cves"]:
                    return mapped_scenario
                if finding_type == "CRED" and vuln_report["weak_credentials_found"]:
                    return mapped_scenario
                if finding_type == "MISC" and vuln_report["misconfigurations_found"]:
                    return mapped_scenario

        return requested

    # ------------------------------------------------------------------
    # BATADAL payload generators
    # ------------------------------------------------------------------

    def _batadal_benign(self) -> dict:
        tank_levels = {f'L_T{i}': round(float(np.random.normal(1.2 + i * 0.1, 0.05)), 4)
                       for i in range(1, 8)}
        pump_flows  = {k: round(abs(float(np.random.normal(v, 0.3))), 4)
                       for k, v in zip(
                           ['F_PU1','F_PU2','F_PU4','F_PU6','F_PU7','F_PU8','F_PU10','F_PU11'],
                           [1.8, 2.1, 1.5, 2.0, 1.7, 1.9, 1.6, 2.2])}
        pump_status = {f'S_PU{i}': int(np.random.choice([0, 1], p=[0.2, 0.8]))
                       for i in [1, 2, 4, 6, 7, 8, 10, 11]}
        pressures   = {k: round(float(np.random.normal(v, 1.0)), 4)
                       for k, v in zip(
                           ['P_J280','P_J269','P_J300','P_J256','P_J289','P_J415',
                            'P_J302','P_J306','P_J307','P_J317','P_J14','P_J422'],
                           [55, 58, 52, 60, 54, 57, 53, 56, 59, 61, 50, 63])}
        return {**tank_levels, **pump_flows, **pump_status,
                'F_V2': round(abs(float(np.random.normal(1.2, 0.1))), 4),
                'S_V2': 1, **pressures}

    def _batadal_pump_attack(self, *, drain: bool = False) -> dict:
        base = self._batadal_benign()
        for k in ['S_PU6', 'S_PU7', 'S_PU11']:
            base[k] = 0
        for k in ['F_PU6', 'F_PU7', 'F_PU11']:
            base[k] = round(abs(float(np.random.normal(0.05, 0.02))), 4)
        if drain:
            base['L_T1'] = round(max(0.1, float(np.random.normal(0.35, 0.05))), 4)
            base['L_T7'] = round(max(0.1, float(np.random.normal(0.28, 0.05))), 4)
        return base

    def _batadal_pressure_attack(self) -> dict:
        base = self._batadal_benign()
        for k in ['P_J280', 'P_J269', 'P_J300', 'P_J256']:
            base[k] = round(float(np.random.normal(base[k] * 1.45, 3.0)), 4)
        return base

    def _batadal_fdia(self) -> dict:
        base = self._batadal_pump_attack(drain=True)
        for k in ['S_PU6', 'S_PU7', 'S_PU11']:
            base[k] = 1
        for k in ['P_J302', 'P_J306', 'P_J307']:
            base[k] = round(float(np.random.normal(base[k] * 1.6, 4.0)), 4)
        return base

    def _add_engineered_features(self, raw: dict) -> dict:
        tank_vals   = [raw[f'L_T{i}'] for i in range(1, 8)]
        pump_flows  = [raw[k] for k in ['F_PU1','F_PU2','F_PU4','F_PU6','F_PU7','F_PU8','F_PU10','F_PU11']]
        pump_status = [raw[f'S_PU{i}'] for i in [1, 2, 4, 6, 7, 8, 10, 11]]
        pressures   = [raw[k] for k in ['P_J280','P_J269','P_J300','P_J256','P_J289','P_J415',
                                         'P_J302','P_J306','P_J307','P_J317','P_J14','P_J422']]
        active_count = sum(pump_status) or 1
        total_flow   = sum(pump_flows)

        def delta(v):    return round(abs(float(np.random.normal(v * 0.05, v * 0.02 + 0.001))), 5)
        def roll_std(v): return round(abs(float(np.random.normal(v * 0.03, v * 0.01 + 0.001))), 5)

        raw.update({
            'mean_tank_level':    round(float(np.mean(tank_vals)), 5),
            'tank_level_std':     round(float(np.std(tank_vals)),  5),
            'min_tank_level':     round(float(np.min(tank_vals)),  5),
            'total_pump_flow':    round(total_flow, 5),
            'active_pump_count':  active_count,
            'mean_pressure':      round(float(np.mean(pressures)), 5),
            'pressure_std':       round(float(np.std(pressures)),  5),
            'pressure_range':     round(float(np.max(pressures) - np.min(pressures)), 5),
            'flow_per_pump':      round(total_flow / active_count, 5),
            'pu6_flow_x_status':  round(raw['F_PU6'] * raw['S_PU6'], 5),
            'pu11_flow_x_status': round(raw['F_PU11'] * raw['S_PU11'], 5),
            'pu7_inactive_flow':  round(raw['F_PU7'] * (1 - raw['S_PU7']), 5),
            'F_PU6_delta':        delta(raw['F_PU6']),
            'F_PU6_rolling_std':  roll_std(raw['F_PU6']),
            'F_PU7_delta':        delta(raw['F_PU7']),
            'F_PU7_rolling_std':  roll_std(raw['F_PU7']),
            'F_PU11_delta':       delta(raw['F_PU11']),
            'F_PU11_rolling_std': roll_std(raw['F_PU11']),
            'L_T1_delta':         delta(raw['L_T1']),
            'L_T1_rolling_std':   roll_std(raw['L_T1']),
            'L_T7_delta':         delta(raw['L_T7']),
            'L_T7_rolling_std':   roll_std(raw['L_T7']),
        })
        return raw

    def _generate_batadal_payload(self, scenario_key: str, scenario: dict) -> dict:
        if scenario_key == 'BENIGN_TRAFFIC':
            raw = self._batadal_benign()
        elif scenario_key in ('LATERAL_MOVEMENT', 'PRIVILEGE_ESCALATION'):
            raw = self._batadal_pump_attack(drain=False)
        elif scenario_key == 'TELEMETRY_SPOOFING':
            raw = self._batadal_pressure_attack()
        else:
            raw = self._batadal_fdia()

        features = self._add_engineered_features(raw)
        base = {
            'scenario_key': scenario_key,
            'mitre_id':     scenario['id'],
            'attack_name':  scenario['name'],
            'target_node':  scenario['target'],
            'severity':     scenario['severity'],
            'features':     features,
        }
        if scenario_key == 'FDIA_PHYSICS_FAILURE':
            base.update({
                'voltage':        round(float(np.random.normal(113.0, 3.0)),  2),
                'current':        round(float(np.random.normal(870.0, 30.0)), 2),
                'active_power':   round(float(np.random.normal(450.0, 20.0)), 2),
                'reactive_power': round(float(np.random.normal(90.0,  5.0)),  2),
            })
        return base

    # ------------------------------------------------------------------
    # SYNTHETIC (8-feature network telemetry) payload generators
    # ------------------------------------------------------------------

    def _generate_synthetic_payload(self, scenario_key: str, scenario: dict) -> dict:
        if scenario_key == 'BENIGN_TRAFFIC':
            features = {
                'flow_duration':            max(10.0, float(np.random.normal(120.0, 45.0))),
                'total_fwd_packets':        int(max(1, np.random.normal(20, 8))),
                'total_bwd_packets':        int(max(1, np.random.normal(15, 6))),
                'packet_length_mean':       max(50.0, float(np.random.normal(250.0, 70.0))),
                'failed_login_attempts':    int(np.random.choice([0, 1], p=[0.92, 0.08])),
                'privilege_escalation_flag': 0,
                'api_response_time_ms':     max(10.0, float(np.random.normal(45.0, 20.0))),
                'unauthorized_port_access': 0,
            }
        elif scenario_key == 'LATERAL_MOVEMENT':
            # Consistent with BlueKeep / S7comm exploitation telemetry:
            # high fwd packets (scanning), elevated failed logins, unauthorized port access
            features = {
                'flow_duration':            float(np.random.normal(1800.0, 500.0)),
                'total_fwd_packets':        int(np.random.normal(180, 50)),
                'total_bwd_packets':        int(np.random.normal(140, 40)),
                'packet_length_mean':       float(np.random.normal(750.0, 200.0)),
                'failed_login_attempts':    int(np.random.poisson(lam=4)),
                'privilege_escalation_flag': int(np.random.choice([0, 1], p=[0.3, 0.7])),
                'api_response_time_ms':     float(np.random.normal(350.0, 100.0)),
                'unauthorized_port_access': int(np.random.choice([0, 1], p=[0.1, 0.9])),
            }
        elif scenario_key == 'PRIVILEGE_ESCALATION':
            # Consistent with Log4Shell / Zerologon: privilege flag + default cred auth
            features = {
                'flow_duration':            float(np.random.normal(1200.0, 350.0)),
                'total_fwd_packets':        int(np.random.normal(110, 30)),
                'total_bwd_packets':        int(np.random.normal(90, 25)),
                'packet_length_mean':       float(np.random.normal(600.0, 150.0)),
                'failed_login_attempts':    int(np.random.poisson(lam=3)),
                'privilege_escalation_flag': 1,
                'api_response_time_ms':     float(np.random.normal(500.0, 150.0)),
                'unauthorized_port_access': int(np.random.choice([0, 1], p=[0.2, 0.8])),
            }
        elif scenario_key == 'FDIA_PHYSICS_FAILURE':
            # Consistent with EternalBlue + DNP3 unauthenticated command injection:
            # mass fwd packets (exploit spray), high API latency (SCADA overload)
            features = {
                'flow_duration':            float(np.random.normal(2400.0, 300.0)),
                'total_fwd_packets':        int(np.random.normal(900, 120)),
                'total_bwd_packets':        int(np.random.normal(50, 20)),
                'packet_length_mean':       float(np.random.normal(1450.0, 150.0)),
                'failed_login_attempts':    int(np.random.poisson(lam=6)),
                'privilege_escalation_flag': 1,
                'api_response_time_ms':     float(np.random.normal(800.0, 200.0)),
                'unauthorized_port_access': 1,
            }
            return {
                'scenario_key':   scenario_key,
                'mitre_id':       scenario['id'],
                'attack_name':    scenario['name'],
                'target_node':    scenario['target'],
                'severity':       scenario['severity'],
                'features':       features,
                'voltage':        round(float(np.random.normal(113.0, 3.0)),  2),
                'current':        round(float(np.random.normal(870.0, 30.0)), 2),
                'active_power':   round(float(np.random.normal(450.0, 20.0)), 2),
                'reactive_power': round(float(np.random.normal(90.0,  5.0)),  2),
            }
        else:  # TELEMETRY_SPOOFING — consistent with OPC-UA anon / SNMP community-string abuse
            features = {
                'flow_duration':            float(np.random.normal(600.0, 200.0)),
                'total_fwd_packets':        int(np.random.normal(650, 180)),
                'total_bwd_packets':        int(np.random.normal(30, 15)),
                'packet_length_mean':       float(np.random.normal(1200.0, 300.0)),
                'failed_login_attempts':    0,
                'privilege_escalation_flag': 0,
                'api_response_time_ms':     float(np.random.normal(1200.0, 400.0)),
                'unauthorized_port_access': 0,
            }

        return {
            'scenario_key': scenario_key,
            'mitre_id':     scenario['id'],
            'attack_name':  scenario['name'],
            'target_node':  scenario['target'],
            'severity':     scenario['severity'],
            'features':     features,
        }
