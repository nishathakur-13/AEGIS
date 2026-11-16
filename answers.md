# AEGIS — Innovation Challenge 2026
## Question & Answer Brief | Cluster 4: IT Security — Improvement of Protection Systems

*Submitted by: Team ResilShield AI | Infosys Innovation Challenge 2026*

---

## Q1. What is your understanding of the problem, how does your solution address it, and what makes it better than existing alternatives?

### Understanding the Problem

The Berlin cable bridge attack in January 2026 made one thing viscerally clear: modern energy infrastructure does not fail in isolation. That incident was physical sabotage — deliberate arson on a cable bridge. AEGIS does not detect arson. But the Berlin event illustrates the systemic risk of concentrated failure points with cascading regional consequences — the same class of risk that emerges when cyber intrusions are allowed to trigger unsafe automated responses in grid control systems. That cyber-physical version is precisely what Cluster 4 is asking for, and it is the specific vulnerability AEGIS is built to close.

But Cluster 4 is not asking about physical fences. It is asking about the IT security layer: the Red and Blue teams, the penetration testing cycles, the alert pipelines, and the defensive hardening procedures that most grid operators today run manually, periodically, and reactively. The core problem is threefold.

First, testing is episodic. A grid operator might commission a penetration test once or twice a year. Between those tests, vulnerabilities accumulate silently.

Second, Red and Blue teams are structurally disconnected. The Red Team probes and documents; the Blue Team receives a report and attempts to patch what it can. There is no live, continuous feedback loop.

Third, and most critically for grid environments specifically, **defensive actions can themselves cause harm**. Isolating a compromised node sounds like straightforward security. In a power grid, it can trigger a cascading overload on adjacent transmission lines. A security decision that is technically correct can be operationally catastrophic. This is a failure mode that every pure-IT security tool on the market is entirely blind to — and it is the failure mode that caused the Northeast US Blackout of 2003.

### How AEGIS Addresses It: The Core Pipeline

The single most important thing AEGIS does is not detect threats — it is **verify that its own proposed responses will not turn a cyber incident into a physical blackout**.

Every cycle in AEGIS runs a full two-phase attack lifecycle before a defensive action reaches a human operator:

```
RECON & VULN DISCOVERY → EXPLOITATION → DETECTION → PROPOSED MITIGATION → PHYSICS SIMULATION → SAFE / UNSAFE → HUMAN APPROVAL
```

**Phase 1 — Reconnaissance & Vulnerability Discovery (genuine Red Teaming)**

Before generating any attack telemetry, AEGIS runs a `VulnerabilityScanner` against the target node's simulated asset inventory. This mirrors what a real penetration tester would do with Nmap, Shodan, and Metasploit:

- **Port scan** — enumerate open services (Modbus/502, S7comm/102, RDP/3389, DNP3/20000, OPC-UA/4840, SMB/445…)
- **CVE matching** — check service versions against real CVE IDs with CVSS scores (e.g. CVE-2019-0708 BlueKeep on RDP, CVE-2021-44228 Log4Shell on PI Server, CVE-2017-0144 EternalBlue on SMB)
- **Credential audit** — test default/weak credentials (admin/admin on HTTP consoles, piadmin/piadmin on PI Data Archive, blank root password on MySQL)
- **Misconfiguration audit** — flag unauthenticated Modbus, SNMPv1 with community string "public", OPC-UA with Anonymous policy, DNP3 without Secure Authentication

The scanner returns a structured `vuln_report`: risk rating (CRITICAL/HIGH/MEDIUM/LOW), the highest-CVSS exploitable finding, and a recommended attack vector derived from what was actually discovered. The attack scenario is then *resolved from findings*, not hardcoded — if EternalBlue is found on SMB, the simulator selects FDIA; if Log4Shell is found on the EMS database, it selects Privilege Escalation.

**Phase 2 — Exploitation & Payload Generation**

The selected attack vector drives statistically realistic telemetry generation. The telemetry is not generic noise — it is shaped to be consistent with the specific exploitation method discovered in Phase 1: BlueKeep exploitation produces lateral movement network patterns; Log4Shell/Zerologon produces privilege escalation signatures; unauthenticated DNP3 commands produce FDIA physics-inconsistent telemetry. Every payload carries the full `vuln_report` as provenance.

**Phase 3–6 — Detection → Mitigation → Physics → Human Approval**

1. **Detection** — The ML ensemble scores the payload; the Uncertainty Engine routes by confidence
2. **Proposed Mitigation** — The Mitigation Engine selects the strongest candidate defensive action
3. **Physics Simulation** — The Physics Twin simulates that action: line loading, transformer utilisation, frequency, breaker status, load redistribution
4. **Safe / Unsafe verdict** — The **Physics Safety Gate** auto-substitutes if the action would overload the grid
5. **Human Approval** — Only a physics-validated, pre-tested action reaches the operator

This full chain guarantees that no defensive action the system recommends can turn a cyber incident into a physical blackout. No commercial ICS security product today implements both phases.

### What Makes It Better Than Existing Alternatives

Current SCADA security products fall into two camps. IT-layer tools — SIEMs, IDS platforms, EDR products — understand network traffic but are completely blind to physical-layer implications. If a compromised sensor reports a false voltage reading, a SIEM sees nothing unusual in the network logs. OT-layer tools from vendors like Claroty, Dragos, and Nozomi Networks monitor industrial protocols and asset inventories, but they are rule-based, reactive, and have no concept whatsoever of whether their recommended isolations are safe from a grid physics perspective.

AEGIS does something neither category does: it treats the security decision and the operational safety check as a single inseparable unit. The Physics Safety Gate — which automatically substitutes a grid-safe alternative when a proposed security action would cause a cascading blackout — is, to our knowledge, a genuinely novel contribution to the field. It is built as an architectural guarantee, not an optional configuration flag.

Beyond the Physics Safety Gate, AEGIS is a complete Purple Team platform. The ML ensemble (four architecturally distinct classifiers) detects the attacks. The Epistemic Uncertainty Engine measures model confidence and routes accordingly. The Conditional Diffusion Generator produces novel, physics-verified zero-day payloads to harden the ensemble against threats that have never been observed. The Human-in-the-Loop gate satisfies EU AI Act Article 14. The full audit trail maps every event to NIS2, IEC 62443, and the EU AI Act. Every cycle, the system attacks itself, detects the attack, validates its response, and learns. The security posture improves continuously.

---

## Q2. How have constraints around cost, infrastructure, resources, or skills shaped your solution, and how does it deliver maximum value with minimal complexity?

### The Real Constraints We Designed Around

I want to be honest about who actually operates distribution grids in Europe. It is not a handful of well-funded utilities with dedicated AI research teams. It is several hundred DSOs (Distribution System Operators), many of them medium-sized regional operators with lean IT departments, legacy SCADA systems from the 1990s and 2000s, and cybersecurity budgets that compete with every other capital expenditure. A few of these operators do not have a dedicated security team at all — cybersecurity responsibilities sit with a generalist IT administrator who also manages the corporate email server.

This is the actual deployment environment AEGIS was designed for. Not a Tier-1 utility with a 24/7 SOC. A mid-size regional DSO in Bavaria or Romania where the IT team is two people and the annual security budget is €150,000.

### How Each Constraint Shaped a Design Decision

**Cost constraint → open-source stack, no proprietary hardware.** Every dependency in the platform is open source: scikit-learn, XGBoost, CatBoost, PyTorch, Streamlit, Plotly, pandas, numpy, joblib. There is no enterprise license fee, no hardware appliance, no vendor contract required to run the core platform. The entire system deploys on a commodity Linux server or a standard cloud VM. The Tier-3 rural edge deployment runs on a Raspberry Pi 4 (~€75 hardware). This is a deliberate design choice.

**Infrastructure constraint → containerised deployment, SCADA-agnostic integration.** AEGIS connects to existing SCADA infrastructure via standard REST or MQTT interfaces in read-only mode. It does not require SCADA upgrades, proprietary adapters, or changes to existing OT network architecture. The system proposes actions; all enforcement goes through the operator's existing control systems after human approval.

**Skills constraint → a SOC dashboard designed for operators, not data scientists.** The interface was built with a specific user in mind: an experienced grid operator who understands voltage and current but has never trained a machine learning model. The dashboard presents verdicts in plain language. Individual model probabilities and physics residuals are visible for transparency, but the operator's job is to read one verdict and make one decision: approve or reject.

**Resource constraint → frugal architecture, three-tier deployment model.** The three-tier deployment model (full AEGIS for critical nodes, ensemble-only for distribution nodes, lightweight anomaly detection for rural endpoints) ensures that resource-intensive components are only deployed where the risk justifies the cost.

### The Complexity Budget

The system has eight functional modules, four pre-trained model files, one configuration layer, and one dashboard entry point. A developer with intermediate Python skills can read and understand the entire codebase in a day. Complexity is a maintenance liability. A system that only a PhD data scientist can maintain will not survive the second year of operation at a DSO with a two-person IT team.

---

## Q3. How is your solution suitable for the European market, mention any adaptations needed including specific regulatory, infrastructure, or customer context changes, and which other global markets face similar constraints where your solution would apply?

### European Market Fit

AEGIS was designed explicitly for the European regulatory and operational context. The three pillars of European critical infrastructure security law — NIS2 Directive (2022/2555), IEC 62443, and the EU AI Act — are not afterthoughts. They are hardcoded into the audit architecture from the ground up.

The NIS2 Directive's Article 21 requirement for "appropriate and proportionate technical and organisational measures" maps directly to the Blue Team Ensemble (technical measure), the Compliance Audit Logger (organisational measure), and the Human-in-the-Loop gate (proportionality — automated systems that can cut power to thousands of households require human oversight). The IEC 62443 Section 4-2 requirements for IACS security map to the physics verification layer and the Digital Twin Sandbox's pre-validation of all patches before deployment. The EU AI Act's Article 14 human oversight requirement for high-risk AI systems — which energy infrastructure AI explicitly is — is satisfied by the architectural guarantee that no hardening action deploys without explicit human analyst authorization. This is not a UI feature. It is enforced at the code architecture level.

The Berlin incident, and the broader category of cascading single-point failures it represents, is the context in which Cluster 4 was written. AEGIS addresses the cyber-physical version of that failure class — remote manipulation of grid control systems via compromised SCADA, false data injection, and unauthenticated OT protocol abuse. The physics engine uses 138 kV and 150 MW parameters representative of European high-voltage distribution standards — and now models eight independent electrical signals: voltage deviation, current/overcurrent, active/reactive power balance, power-flow imbalance, breaker status, load redistribution, frequency droop, and line/transformer loading.

### Adaptations Needed for Full EU Deployment

**GDPR Article 25 (Data Protection by Design):** The current system processes operational telemetry, not personal data. However, in a production deployment, SCADA login event metadata could constitute personal data under GDPR's broad definition. The audit log schema would need a data minimisation review.

**EN 50160 and ENTSO-E Grid Codes:** The physics engine currently uses simplified 3-phase power flow equations with configurable voltage and capacity parameters. A production deployment targeting a specific DSO's grid topology would need calibration to that operator's actual network parameters — nominal voltage levels, rated line capacities, N-1 security criteria. This is a configuration exercise, not an architectural change.

**Language localisation:** The SOC dashboard is entirely in English. For deployment across EU member states, UI strings and alert messages would need localisation.

**Integration with national CERT infrastructure:** Under NIS2, DSOs are required to report significant incidents to their national CSIRT. The compliance logger currently writes to a local structured log file. A production version would need a secure outbound reporting module.

### Other Global Markets with Similar Constraints

The underlying problem — legacy ICS/SCADA systems, resource-constrained regional utilities, escalating cyber-physical threat profile, growing regulatory pressure — is not unique to Europe.

**Japan:** TEPCO and the regional electric power companies operate aging SCADA infrastructure with strict physical-layer safety requirements. The Physics Safety Gate is particularly relevant in Japan's earthquake-prone grid environment. AEGIS would need adaptation to Japan's grid standards and NISC compliance reporting.

**Australia:** The Australian Energy Sector Cybersecurity Framework (AESCF) and the Critical Infrastructure Risk Management Program create a regulatory demand exactly parallel to NIS2. Australian grid operators, particularly in Western Australia and Queensland, face exactly the connectivity constraints that AEGIS's edge deployment model addresses.

**India:** The Central Electricity Authority's cybersecurity guidelines mandate continuous monitoring, incident response, and audit trails for critical power infrastructure. India's distribution grid is operated by hundreds of state-level DISCOMs with highly variable IT maturity and limited cybersecurity budgets. The frugal engineering model is essentially designed for this environment. Adaptation would require calibration to Indian grid standards (33 kV, 11 kV distribution voltages) and integration with CERT-In.

The core physics laws are universal. Kirchhoff's current law does not change between Frankfurt and Kuala Lumpur. Only the parameter calibration and regulatory compliance mapping require market-specific adaptation.

---

## Q4. How would your idea be validated within the first 12 months, what would be tested, in what environment, and what would it prove? After validation, what is your deployment path for EU and global markets?

### Validation Philosophy

There is a specific kind of failure I want to avoid: a lab demonstration that looks impressive in a controlled environment and then fails silently in production because real ICS telemetry is messier, noisier, and more temporally correlated than anything a synthetic data generator produces. The BATADAL validation on real attack data was the first step. But a dataset benchmark is not a field deployment.

### Phase 0 (Months 0–2): Internal Technical Validation

Already complete. 5-fold stratified cross-validation on 4,177 real BATADAL sensor records (XGBoost CV AUC: 0.993 ± 0.003; CatBoost CV AUC: 0.992 ± 0.004). The ablation study proves that each architectural component contributes measurable, reproducible security improvement. Critically, the **Physics Safety Gate is tested end-to-end**: a simulated FDIA scenario that would have caused 87.5% cascading failure risk is intercepted and the action downgraded to DYNAMIC_MICRO_SEGMENTATION automatically — with no human intervention required.

### Phase 1 (Months 2–4): Sandbox Pilot — Simulated DSO Environment

- **What is tested:** Full AEGIS pipeline running against a replayed, anonymised SCADA telemetry stream from a willing DSO partner. Physics Twin calibrated to the specific DSO's voltage and capacity parameters. Human-in-the-Loop approval workflow tested with actual grid operators.
- **Specific Physics Safety Gate test:** A planned network switching operation is fed through the system to verify the gate correctly identifies it as safe and does not trigger a false threat alarm.
- **Environment:** Air-gapped simulation environment on the DSO's corporate IT network, not connected to any operational OT system.
- **What it proves:** That the physics pipeline (including Safety Gate logic) is operationally usable by actual grid operators and calibrates correctly to a real DSO topology.

### Phase 2 (Months 4–9): Live Pilot — Read-Only OT Network Access

- **What is tested:** AEGIS connected to a live SCADA telemetry feed in read-only, alert-only mode. Physics gate is monitored in shadow mode — every action recommendation is logged alongside what the gate would have done, but nothing is deployed.
- **Environment:** One EU DSO Tier-1 substation. OT-segmented network. Read-only access only.
- **What it proves:** That the physics model's safety assessments align with the DSO's own engineering team's assessment of which actions are safe under real grid conditions.

### Phase 3 (Months 9–12): Controlled Deployment Pilot

- **What is tested:** Full pipeline with Human-in-the-Loop gate activated. Two Tier-1 nodes. Physics Safety Gate tested against a planned switching operation to verify it does not false-alarm.
- **What it proves:** End-to-end operational capability, including the core claim: a security action recommended by AEGIS and approved through the HITL gate does not cause grid disruption.

### Post-Validation Deployment Path

**EU expansion (Months 13–24):** Target 10–20 Tier-1 deployments across three to four EU member states, prioritising markets with active NIS2 enforcement.

**Global adaptation (Months 18–36):** Adapt physics parameters and compliance logging for Japan, Australia, and India. Engage local OT system integrators as the go-to-market channel.

---

## Q5. Describe your solution's end-to-end technical architecture, listing all major components, integration points, and open-source tools used. How does your design ensure simplicity and robustness?

### End-to-End Architecture: The Pipeline First

Before listing components, it helps to understand the pipeline that connects them. Every simulation cycle follows this path:

```
ATTACK (Red Team)
    ↓
DETECTION (ML Ensemble + Uncertainty Engine)
    ↓
PROPOSED MITIGATION (Mitigation Engine + Digital Twin Sandbox)
    ↓
PHYSICS SIMULATION (Physics-Informed Digital Twin)
    ↓ checks: voltage deviation · current/overcurrent · active & reactive power
    ↓         power-flow imbalance · breaker status · load redistribution
    ↓         frequency droop · line loading · transformer loading
    ↓
SAFE / UNSAFE verdict → if unsafe: Physics Safety Gate fires, action downgraded
    ↓
CRI FUSION (Integrated Safety Report Engine)
    ↓ CRI = 0.45×ML + 0.30×Physics + 0.10×KCL + 0.10×Frequency + 0.05×Transformer
    ↓
HUMAN APPROVAL (HITL Gate — EU AI Act Article 14)
    ↓
COMPLIANCE LOG (NIS2 · IEC 62443 · EU AI Act — every event)
```

This is not a description of a future design. It is the active code path running in the submitted application.

### Component-by-Component

**SOC Dashboard — Streamlit Entry Point**
The user-facing application layer. Three operational zones: Live SOC Operations, Research Experiments & Ablation Study, and GenAI Zero-Day Lab. Interactive visualisations powered by Plotly.

**System Configuration Module**
Single source of truth for all thresholds, feature column definitions (8-feature synthetic mode + 59-feature BATADAL mode), attack scenario mappings, compliance framework strings, and the active dataset mode switch.

**Red Team Simulator**
Implements a genuine two-phase attack lifecycle. Phase 1: `VulnerabilityScanner` probes a simulated asset inventory of five grid nodes, each with a realistic OS/firmware profile, open ports and services, real CVE IDs with CVSS scores, default/weak credentials, and known OT misconfigurations. The scanner performs port enumeration, CVE matching, credential auditing, and misconfiguration detection — mirroring what Nmap, Shodan, and Metasploit would find in a real OT environment. The highest-severity finding drives attack vector selection via `_resolve_scenario()`. Phase 2: statistically realistic telemetry is generated *consistent with the specific exploitation method discovered* — BlueKeep RDP exploitation produces lateral movement network signatures; Log4Shell/Zerologon produces privilege escalation patterns; unauthenticated DNP3 command injection produces FDIA physics-inconsistent telemetry. Every non-benign payload carries the full `vuln_report` as provenance. Gaussian, Poisson, and exponential noise injected throughout to prevent trivially separable distributions.

**Blue Team Ensemble**
Four architecturally distinct classifiers: Random Forest (300 trees, bagging), Extra Trees (300 trees, extreme randomisation), XGBoost (300 rounds, sequential gradient boosting), CatBoost (300 iterations, categorical boosting). The heterogeneity is deliberate: convergence across fundamentally different learning algorithms is genuine evidence; their disagreement is a primary security signal.

**Epistemic Uncertainty Engine**
Computes mean (composite threat score) and variance (σ²) across the four model probabilities. Routes to HIGH_CONFIDENCE_THREAT, HIGH_UNCERTAINTY_ANOMALY, BENIGN_CLEAR, or AMBIGUOUS_MONITOR based on both signal. High variance → human escalation, not automated action.

**Physics-Informed Digital Twin**
The most critical component. `verify_physical_laws()` checks eight independent electrical signals against every telemetry packet:

| Signal | Method | Threshold |
|---|---|---|
| Power-flow imbalance | \|S_measured − √3·V·I/1000\| / S_calculated | ≤ 8% |
| Voltage deviation | \|V − V_nominal\| / V_nominal | Warning ≤ 5%; Trip ≤ 10% |
| Active / reactive power | Direct measurement + Q/P ratio | Q/P > 0.6 = high-reactive flag |
| Apparent power | S = √(P² + Q²) | consistency cross-check |
| Current / overcurrent | I > 1.10 × I_rated | Binary flag |
| Frequency estimation | Δf = −D × (P_imbalance / P_rated), D = 5 Hz/pu | ±0.5 Hz trip band |
| Breaker status | Trips on overcurrent OR voltage > ±10% OR \|Δf\| > 0.5 Hz | Per-node tracking |
| Line / transformer loading | S / capacity × 100%, S / 160 MVA × 100% | Trip at 110% transformer |

`simulate_mitigation_safety()` then models what happens to the grid if the proposed action is deployed:
- Load redistribution: FULL_NODE_ISOLATION forces 3 adjacent lines to absorb 135% of shed load
- Per-line loading computed individually
- Transformer loading post-event
- Frequency droop post-event (ROCOF model)
- Per-node breaker status (source_bus, load_bus, target_node)

**The Physics Safety Gate** fires when `line_stress_pct > 100%` after redistribution. It automatically substitutes FULL_NODE_ISOLATION with DYNAMIC_MICRO_SEGMENTATION and flags the override to the operator. The blackout is prevented before the operator ever sees the recommendation.

**Integrated Safety Report Engine**
Fuses all signals into the Combined Risk Index:

```
CRI = 0.45 × ML_threat_score
    + 0.30 × physics_anomaly_score
    + 0.10 × KCL_overcurrent_score
    + 0.10 × frequency_score
    + 0.05 × transformer_score

physics_anomaly_score = 0.55 × norm(power_residual / 8%)
                      + 0.30 × norm(voltage_deviation / 5%)
                      + 0.15 × high_reactive_flag

frequency_score       = min(|Δf| / 0.5 Hz, 1.0)
transformer_score     = min(transformer_loading / 110%, 1.0)
```

Verdict tiers: CRITICAL_CONFIRMED (CRI ≥ 0.80), HIGH_THREAT (≥ 0.55), AMBIGUOUS_MONITOR (≥ 0.30), BENIGN_CLEAR (< 0.30).

**Mitigation Engine + Digital Twin Sandbox**
Selects a candidate patch, replays the attack in an air-gapped ephemeral sandbox, computes security gain and disruption dynamically, and returns a pre-validated patch report. Only after sandbox validation does the patch reach the operator.

**Conditional Diffusion Generator**
PyTorch neural network. Starts with pure Gaussian noise. Runs 100 iterative denoising steps conditioned on attack severity (0.25 LOW → 1.0 CRITICAL). Maps to SCADA telemetry scale. Runs every generated payload through the Physics Twin — physics-inconsistent outputs are classified as genuine FDIA zero-day vectors. Feeds back into adversarial ensemble retraining.

**Compliance Audit Logger**
Every event is written to `logs/audit_compliance_trail.json` with explicit cross-references to NIS2 Article 21, IEC 62443 Section 4-2, and EU AI Act Article 14.

**Ablation Benchmark Engine**
Trains and evaluates all five architecture tiers from scratch across N random seeds. Full AEGIS achieves 0% FPR versus 4.53–4.66% for single-model baselines.

**BATADAL Training Pipeline**
59-feature engineering, stratified 5-fold cross-validation, all four model artefacts plus the fitted scaler serialised to disk.

### Open-Source Tools

| Tool | Purpose |
|---|---|
| Streamlit ≥1.30.0 | SOC Dashboard UI |
| scikit-learn ≥1.3.0 | Random Forest, Extra Trees, StandardScaler, cross-validation |
| XGBoost ≥2.0.0 | Gradient boosting classifier |
| CatBoost ≥1.2.0 | Categorical boosting classifier |
| PyTorch | Conditional Diffusion Model neural network |
| pandas ≥2.0.0 | Data processing and feature engineering |
| NumPy ≥1.24.0 | Numerical computation, physics calculations |
| Plotly ≥5.18.0 | Interactive visualisations |
| joblib ≥1.3.0 | Model serialisation and loading |

No cloud APIs. No external services. No internet connection required at runtime.

### Simplicity and Robustness

The entire platform is approximately 2,500 lines of Python across nine files. No microservices, no message queues, no distributed systems. Every module has one clear responsibility. The physics twin's conservation law checks use only arithmetic operations with no external library dependencies — they cannot fail due to a version conflict. If model artefacts are not found on disk, the ensemble loader triggers automatic retraining rather than crashing. The compliance logger wraps all file I/O in error handling that reinitialises from an empty state on parse failure, preventing log corruption from causing an application crash.

---

## Q6. Are there known regulatory, safety, or standards barriers to deploying your solution? Does it process personal data or use AI for decisions? What co-innovation dependencies are required and what is your timeline to deployment?

### Regulatory and Standards Barriers

**EU AI Act classification:** AEGIS uses AI to produce security assessments affecting critical infrastructure — explicitly high-risk under Annex III. The Human-in-the-Loop architecture and full explainability are purpose-built to satisfy Article 14. The persistent audit trail satisfies Article 12. The ablation study and BATADAL validation satisfy Article 9. The barrier is real but manageable — an 18-to-24-month compliance and certification process.

**NIS2 Directive and KRITIS (Germany):** AEGIS must be certifiable as contributing to, not undermining, the operator's NIS2 compliance posture. The compliance audit trail and regulatory mapping are specifically designed to produce artefacts that a DSO can present to their national competent authority as evidence of Article 21 compliance.

**IEC 62443 component certification:** A commercial version would need IEC 62443-4-1 assessment. Typically 6–12 months and €50,000–€150,000. One-time cost that creates a durable competitive advantage.

### Personal Data Processing

The system processes operational telemetry: sensor readings, SCADA event timestamps, network flow metadata. In normal operation, this is not personal data. Edge cases exist (SCADA login event logs). Standard data minimisation review required for production deployment.

### AI-Driven Decision Making

AEGIS makes threat classifications and patch recommendations. It **does not deploy any action autonomously**. The Human-in-the-Loop gate is an architectural guarantee. The operator who approves a hardening action has seen exactly what the system detected, how confident each model was, whether the physics checks passed (including all eight electrical signals), and what the proposed action will do to transmission line stress, transformer loading, and frequency — before clicking approve.

### Co-Innovation Dependencies

**DSO data partnerships:** Production-quality model retraining requires real SCADA telemetry. The most important co-innovation dependency.

**System integrator partnerships:** Partnerships with OT-specialist system integrators (Phoenix Contact, Siemens Smart Infrastructure, or mid-size OT security integrators in Germany and the Nordics) for deployment capability and customer relationships.

**ICS security research institutions:** Fraunhofer FKIE, ENISA, and BSI for access to larger, more diverse attack datasets.

### Realistic Timeline to Deployment

| Milestone | Timeline |
|---|---|
| Functional prototype, BATADAL validated, Physics Safety Gate live | Now |
| EU AI Act technical documentation complete | +6 months |
| First read-only live pilot with DSO partner | +9 months |
| IEC 62443-4-1 assessment initiated | +12 months |
| First paid pilot deployment (Tier-1 node, one DSO) | +12–15 months |
| IEC 62443 certification complete | +18–24 months |
| 10 DSO deployments across EU | +24–30 months |
| First non-EU market deployment | +30–36 months |

---

## Q7. What is the market opportunity in EU and global markets — target customers, addressable market size, and go-to-market path to first paying customer in Europe?

### Target Customer Segments

**Primary: Mid-size EU Distribution System Operators (DSOs)** — regional operators serving 50,000–500,000 connection points. Large enough to be NIS2 essential entities with mandatory compliance requirements. Small enough that they cannot build something like AEGIS in-house.

**Secondary: National Transmission System Operators (TSOs)** — higher-touch sale, longer procurement cycle, but larger contract value and much higher reference case value.

**Tertiary: OT security system integrators** — companies that currently sell Claroty or Dragos but want a product tier that addresses the cyber-physical safety gap that neither tool covers.

### Addressable Market Estimate

The EU has approximately 2,300 DSOs. Approximately 300 are NIS2-classified essential entities representing the realistic initial serviceable addressable market.

At €8,600 per Tier-1 node per year and an average of 5 Tier-1 nodes per mid-size DSO, each customer represents approximately €43,000 per year. 100 customers = €4.3M ARR at Tier-1 only. Including Tier-2 distribution nodes, the per-customer value grows to approximately €543,000 at full deployment.

The broader EU critical infrastructure IT security market is estimated at ~€800M annually for the energy sector. AEGIS competes for a fraction of this with a specific differentiator — physics-informed, Purple Team automation — that existing tools do not offer.

### Go-to-Market Path

**Route 1 — Horizon Europe research programme:** Apply to cybersecurity calls requiring industry partnership. Creates a funded pilot relationship that naturally evolves into a commercial one. Timeline: 18–24 months.

**Route 2 — Infosys/E.ON partnership leverage:** E.ON operates DSOs across Germany, Sweden, the Czech Republic, and Romania. The challenge outcome itself becomes the commercial lead. Timeline: 9–12 months.

**Route 3 — OT security integrator channel:** Approach a German or Dutch OT security integrator already serving DSOs. AEGIS as a mid-market alternative to enterprise OT security suites is a natural portfolio extension. Timeline: 6–9 months.

Route 2 is preferred given the context of this challenge.

---

## Q8. What is the estimated Total Cost of Ownership (TCO) for deploying your solution at production scale in EU or global markets? Break down production, deployment, and operating costs and quantify the customer savings.

### Customer-Facing TCO: Tier-1 Critical Node (Annual)

| Cost Category | Item | Annual Estimate | Notes |
|---|---|---|---|
| **Infrastructure** | Cloud VM (2 vCPU, 8 GB RAM, standard tier, EU region) | €3,600 | €300/month |
| **Infrastructure** | Persistent storage (50 GB) | €600 | €50/month |
| **Operations** | Quarterly automated model retraining | €400 | ~4 hours GPU-grade compute quarterly |
| **Labour** | Integration and maintenance (5 days/year at €800/day) | €4,000 | Initial year: 15 days (~€12,000) |
| **Licensing** | Open-source stack | €0 | All open source |
| | **Total Tier-1, steady state (Year 2+)** | **~€8,600/year** | |
| | **Total Tier-1, first year (with integration)** | **~€16,600/year** | |

### Regional DSO at Scale (5 Tier-1 + 30 Tier-2 nodes)

| Deployment | Nodes | Annual Cost |
|---|---|---|
| Tier-1 (full AEGIS) | 5 × €8,600 | €43,000 |
| Tier-2 (ensemble-only) | 30 × €2,500 | €75,000 |
| Central AEGIS Platform | 1 × €18,000 | €18,000 |
| **Total annual OpEx (Year 2+)** | | **~€136,000/year** |
| **First-year integration (one-time)** | | **~€80,000** |

### Quantified Customer Savings

**Incident prevention:** A major grid disruption event affecting a European city — whether caused by physical sabotage, as in Berlin, or by a cyber intrusion that triggers unsafe automated grid responses — carries an estimated €20–50M in economic impact (emergency services, business interruption, food spoilage, heating loss, hospital backup systems). At €136,000 annual platform cost, preventing a single incident of that scale delivers 150–370× ROI in the year of prevention alone. AEGIS addresses the cyber-physical vector specifically: an attacker manipulating SCADA to trigger the same cascading electrical consequences.

**NIS2 compliance cost avoidance:** Manual NIS2 compliance through external consultants costs €200,000–€400,000/year. AEGIS automates continuous monitoring, incident logging, and human oversight documentation. Conservative savings: €80,000–€120,000/year — approaching the entire platform cost.

**Fine avoidance:** Maximum NIS2 fines are €10M or 2% of global annual turnover. The annual platform cost is 1.4% of the maximum fine for a mid-size DSO with €500M revenue.

**False positive reduction:** Full AEGIS achieves 0% FPR in ablation testing versus 4.5% for single-model baselines. Reducing false positives from 4.5% to near-zero on 10,000 events saves approximately 450 analyst-hours/year — approximately €180,000 at €400/hour for a certified ICS security analyst.

**Physics Safety Gate ROI:** A single prevented defensive blackout — where AEGIS blocked a legitimate security action that would have triggered a cascading outage — saves the entire annual platform cost in one event.

---

*Infosys Innovation Challenge 2026 | Cluster 4: IT Security — Improvement of Protection Systems*
*Team: ResilShield AI | AEGIS v2.2 | August 2026*
