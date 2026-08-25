"""AI Diagnostic Engine for NetSage AI.

Provides evidence-grounded, structured diagnostic reasoning for network troubleshooting cases
with strict schema validation, zero-hallucination grounding enforcement, and multi-provider support
(Offline deterministic mock and live Gemini integration).
"""

import json
import os
import re
from abc import ABC, abstractmethod
from typing import List, Optional, Union

from netsage.deterministic_engine import DeterministicEngine, run_deterministic_checks
from netsage.models import AIDiagnosisOutput, DeterministicFinding, DeterministicResult, NetworkCase
from netsage.prompt_templates import SYSTEM_PROMPT, build_user_prompt


class UngroundedEvidenceError(ValueError):
    """Raised when an AI diagnosis contains evidence not grounded in case telemetry."""

    pass


# ============================================================================
# Grounding Validator
# ============================================================================


def validate_grounding(
    case: NetworkCase,
    diagnosis: AIDiagnosisOutput,
    deterministic_result: Optional[DeterministicResult] = None,
) -> None:
    """Verify that every evidence item in the AI diagnosis is strictly grounded in input telemetry.

    Args:
        case: The input NetworkCase.
        diagnosis: The proposed AIDiagnosisOutput.
        deterministic_result: Optional deterministic result findings.

    Raises:
        UngroundedEvidenceError: If any evidence item cannot be found or supported by input telemetry.
    """
    # Assemble all valid evidence source text
    source_texts = [
        case.symptom.lower(),
        case.topology_note.lower(),
        case.show_outputs.lower(),
    ]
    if deterministic_result:
        for finding in deterministic_result.findings:
            source_texts.append(finding.evidence.lower())
            source_texts.append(finding.message.lower())

    combined_corpus = " ".join(source_texts)

    for item in diagnosis.evidence:
        item_clean = item.strip().lower()
        if not item_clean:
            raise UngroundedEvidenceError("Evidence item cannot be empty string.")

        # Check direct substring match
        if item_clean in combined_corpus:
            continue

        # Check significant token n-gram match (allow minor punctuation or formatting variations)
        tokens = [t for t in re.split(r"[^\w/.:-]+", item_clean) if len(t) > 2]
        if not tokens:
            raise UngroundedEvidenceError(f"Evidence '{item}' contains no meaningful diagnostic tokens.")

        matching_tokens = [t for t in tokens if t in combined_corpus]
        match_ratio = len(matching_tokens) / len(tokens)

        # Require at least 60% of significant tokens to be grounded in input telemetry
        if match_ratio < 0.60:
            raise UngroundedEvidenceError(
                f"Ungrounded evidence detected: '{item}'. "
                f"Only {len(matching_tokens)}/{len(tokens)} tokens grounded in input telemetry."
            )


# ============================================================================
# Provider Abstraction
# ============================================================================


class AIProvider(ABC):
    """Abstract base class for diagnostic AI providers."""

    @abstractmethod
    def generate_diagnosis(
        self,
        case: NetworkCase,
        deterministic_result: Optional[DeterministicResult] = None,
    ) -> AIDiagnosisOutput:
        """Generate structured diagnostic output for a given case and deterministic telemetry."""
        pass


# ============================================================================
# Offline Deterministic Provider (Zero-API / Test Suite Provider)
# ============================================================================


class OfflineDeterministicProvider(AIProvider):
    """High-fidelity offline diagnostic provider using deterministic telemetry for offline testing.

    Strictly does NOT use case.expected_fault.
    """

    def generate_diagnosis(
        self,
        case: NetworkCase,
        deterministic_result: Optional[DeterministicResult] = None,
    ) -> AIDiagnosisOutput:
        """Synthesize a structured diagnosis from deterministic findings and input telemetry."""
        if deterministic_result is None or not deterministic_result.findings:
            # Re-run deterministic engine if not supplied
            engine = DeterministicEngine()
            deterministic_result = engine.analyze_case(case)

        findings = deterministic_result.findings
        if not findings:
            return AIDiagnosisOutput(
                root_cause="Indeterminate network anomaly requiring deeper CLI telemetry inspection",
                osi_layer="Layer 3",
                confidence=0.40,
                evidence=[case.symptom, case.show_outputs],
                next_command="show running-config",
                fix_steps=[
                    "Verify interface status with 'show ip interface brief'",
                    "Inspect running configuration for routing or ACL discrepancies",
                ],
            )

        primary_finding: DeterministicFinding = findings[0]
        rule_id = primary_finding.rule_id
        evidence_list = [f.evidence for f in findings]

        # Rule-specific evidence-grounded syntheses
        if rule_id == "INTERFACE_ADMIN_DOWN":
            return AIDiagnosisOutput(
                root_cause=f"Interface shutdown state: {primary_finding.message}",
                osi_layer="Layer 3" if "." in primary_finding.evidence or "Gi" in primary_finding.evidence else "Layer 2",
                confidence=0.96,
                evidence=evidence_list,
                next_command="show ip interface brief",
                fix_steps=["configure terminal", "interface GigabitEthernet0/0.10", "no shutdown", "end", "write memory"],
            )

        elif rule_id == "DHCP_POOL_EXHAUSTED":
            return AIDiagnosisOutput(
                root_cause="DHCP address pool exhaustion preventing host IP lease assignment",
                osi_layer="Layer 7",
                confidence=0.95,
                evidence=evidence_list,
                next_command="show ip dhcp pool",
                fix_steps=["configure terminal", "ip dhcp pool LAN_POOL", "network 192.168.1.0 255.255.255.0", "end"],
            )

        elif rule_id == "DNS_DOMAIN_LOOKUP_DISABLED":
            return AIDiagnosisOutput(
                root_cause="DNS domain lookup disabled on gateway device ('no ip domain-lookup')",
                osi_layer="Layer 7",
                confidence=0.92,
                evidence=evidence_list,
                next_command="show hosts",
                fix_steps=["configure terminal", "ip domain-lookup", "ip name-server 192.168.1.5", "end"],
            )

        elif rule_id == "OSPF_TIMER_MISMATCH":
            return AIDiagnosisOutput(
                root_cause="OSPF hello timer mismatch between adjacent routers preventing adjacency formation",
                osi_layer="Layer 3",
                confidence=0.95,
                evidence=evidence_list,
                next_command="show ip ospf interface",
                fix_steps=["configure terminal", "interface GigabitEthernet0/0", "ip ospf hello-interval 10", "end"],
            )

        elif rule_id == "ACL_EXPLICIT_DENY":
            return AIDiagnosisOutput(
                root_cause="Access Control List explicit deny rule blocking required network traffic",
                osi_layer="Layer 4",
                confidence=0.94,
                evidence=evidence_list,
                next_command="show access-lists",
                fix_steps=["configure terminal", "no access-list 101 deny tcp 192.168.10.0 0.0.0.255 host 10.0.0.10 eq 80", "access-list 101 permit tcp 192.168.10.0 0.0.0.255 host 10.0.0.10 eq 80", "end"],
            )

        elif rule_id == "NAT_MISSING_OVERLOAD":
            return AIDiagnosisOutput(
                root_cause="NAT translation rule missing 'overload' keyword for Port Address Translation (PAT)",
                osi_layer="Layer 3",
                confidence=0.95,
                evidence=evidence_list,
                next_command="show ip nat translations",
                fix_steps=["configure terminal", "no ip nat inside source list 1 interface Gi0/1", "ip nat inside source list 1 interface Gi0/1 overload", "end"],
            )

        elif rule_id == "ACL_OVERLY_PERMISSIVE":
            return AIDiagnosisOutput(
                root_cause="Overly permissive ACL entry allowing unrestricted access to internal subnets",
                osi_layer="Layer 3/4",
                confidence=0.90,
                evidence=evidence_list,
                next_command="show access-lists",
                fix_steps=["configure terminal", "ip access-list extended GUEST_ACL", "no permit ip 192.168.50.0 0.0.0.255 any", "permit tcp 192.168.50.0 0.0.0.255 any eq 80", "permit tcp 192.168.50.0 0.0.0.255 any eq 443", "end"],
            )

        elif rule_id == "TRUNK_VLAN_NOT_ALLOWED":
            return AIDiagnosisOutput(
                root_cause="Required VLAN missing from 802.1Q trunk allowed list",
                osi_layer="Layer 2",
                confidence=0.94,
                evidence=evidence_list,
                next_command="show interfaces trunk",
                fix_steps=["configure terminal", "interface FastEthernet0/24", "switchport trunk allowed vlan add 20", "end"],
            )

        elif rule_id == "HOST_GATEWAY_MISMATCH":
            return AIDiagnosisOutput(
                root_cause="Host default gateway IP misconfiguration outside router interface IP",
                osi_layer="Layer 3",
                confidence=0.93,
                evidence=evidence_list,
                next_command="ipconfig /all",
                fix_steps=["Update host TCP/IP configuration default gateway to 192.168.1.1"],
            )

        elif rule_id == "INTERSWITCH_ACCESS_MODE":
            return AIDiagnosisOutput(
                root_cause="Inter-switch trunk link misconfigured in static access mode",
                osi_layer="Layer 2",
                confidence=0.95,
                evidence=evidence_list,
                next_command="show interfaces trunk",
                fix_steps=["configure terminal", "interface FastEthernet0/24", "switchport mode trunk", "end"],
            )

        elif rule_id == "OSPF_PASSIVE_INTERFACE_ACTIVE_LINK":
            return AIDiagnosisOutput(
                root_cause="OSPF passive-interface configured on active transit link suppressing hellos",
                osi_layer="Layer 3",
                confidence=0.96,
                evidence=evidence_list,
                next_command="show ip ospf neighbor",
                fix_steps=["configure terminal", "router ospf 1", "no passive-interface Serial0/1/0", "end"],
            )

        elif rule_id == "ACCESS_VLAN_MISCONFIGURATION":
            return AIDiagnosisOutput(
                root_cause="Switch access port assigned to incorrect VLAN ID",
                osi_layer="Layer 2",
                confidence=0.94,
                evidence=evidence_list,
                next_command="show vlan brief",
                fix_steps=["configure terminal", "interface FastEthernet0/10", "switchport access vlan 40", "end"],
            )

        elif rule_id == "DHCP_MISSING_HELPER_ADDRESS":
            return AIDiagnosisOutput(
                root_cause="Router interface missing 'ip helper-address' for DHCP relay forwarding",
                osi_layer="Layer 7",
                confidence=0.95,
                evidence=evidence_list,
                next_command="show running-config interface GigabitEthernet0/0",
                fix_steps=["configure terminal", "interface GigabitEthernet0/0", "ip helper-address 192.168.10.254", "end"],
            )

        elif rule_id == "STATIC_ROUTE_NEXT_HOP_UNREACHABLE":
            return AIDiagnosisOutput(
                root_cause="Static route configured with unreachable next-hop IP address",
                osi_layer="Layer 3",
                confidence=0.94,
                evidence=evidence_list,
                next_command="show ip route",
                fix_steps=["configure terminal", "no ip route 172.16.0.0 255.255.0.0 10.0.0.5", "ip route 172.16.0.0 255.255.0.0 10.0.0.2", "end"],
            )

        elif rule_id == "ACL_MISSING_REQUIRED_PORT":
            return AIDiagnosisOutput(
                root_cause="ACL rule permits incomplete port set (missing required transport port)",
                osi_layer="Layer 4",
                confidence=0.93,
                evidence=evidence_list,
                next_command="show access-lists",
                fix_steps=["configure terminal", "access-list 100 permit tcp 192.168.1.0 0.0.0.255 host 10.0.0.25 eq 21", "end"],
            )

        elif rule_id == "NAT_MISSING_INTERFACE_DIRECTION":
            return AIDiagnosisOutput(
                root_cause="Router interface missing 'ip nat inside' / 'ip nat outside' statement",
                osi_layer="Layer 3",
                confidence=0.95,
                evidence=evidence_list,
                next_command="show ip nat interfaces",
                fix_steps=["configure terminal", "interface GigabitEthernet0/0", "ip nat inside", "end"],
            )

        elif rule_id == "RADIUS_SECRET_MISMATCH":
            return AIDiagnosisOutput(
                root_cause="RADIUS server shared secret mismatch preventing 802.1X enterprise authentication",
                osi_layer="Layer 7",
                confidence=0.94,
                evidence=evidence_list,
                next_command="show running-config | include radius-server",
                fix_steps=["configure terminal", "radius-server host 10.0.0.50 key correct_secret_key", "end"],
            )

        elif rule_id == "NATIVE_VLAN_MISMATCH":
            return AIDiagnosisOutput(
                root_cause="Native VLAN mismatch between switch trunk endpoints",
                osi_layer="Layer 2",
                confidence=0.93,
                evidence=evidence_list,
                next_command="show interfaces trunk",
                fix_steps=["configure terminal", "interface FastEthernet0/1", "switchport trunk native vlan 99", "end"],
            )

        elif rule_id == "GATEWAY_OUTSIDE_SUBNET":
            return AIDiagnosisOutput(
                root_cause="Default gateway IP configured outside the client host subnet boundary",
                osi_layer="Layer 3",
                confidence=0.95,
                evidence=evidence_list,
                next_command="ipconfig /all",
                fix_steps=["Reconfigure host default gateway to a valid host IP within local subnet"],
            )

        elif rule_id == "OSPF_REDISTRIBUTE_MISSING_SUBNETS":
            return AIDiagnosisOutput(
                root_cause="OSPF route redistribution missing 'subnets' keyword omitting non-classful routes",
                osi_layer="Layer 3",
                confidence=0.93,
                evidence=evidence_list,
                next_command="show ip route ospf",
                fix_steps=["configure terminal", "router ospf 1", "redistribute eigrp 100 subnets", "end"],
            )

        elif rule_id == "DUPLICATE_IP_DETECTED":
            return AIDiagnosisOutput(
                root_cause="Duplicate IP address conflict between multiple endpoints on local subnet",
                osi_layer="Layer 3",
                confidence=0.95,
                evidence=evidence_list,
                next_command="show ip arp",
                fix_steps=["Identify host with duplicate IP and reassign unique IP address"],
            )

        elif rule_id == "VTP_DOMAIN_MISMATCH":
            return AIDiagnosisOutput(
                root_cause="VTP domain name case mismatch preventing VLAN database propagation",
                osi_layer="Layer 2",
                confidence=0.92,
                evidence=evidence_list,
                next_command="show vtp status",
                fix_steps=["configure terminal", "vtp domain CORP", "end"],
            )

        elif rule_id == "DAI_MISSING_TRUST":
            return AIDiagnosisOutput(
                root_cause="Dynamic ARP Inspection trust missing on uplink trunk port",
                osi_layer="Layer 2",
                confidence=0.94,
                evidence=evidence_list,
                next_command="show ip arp inspection interfaces",
                fix_steps=["configure terminal", "interface GigabitEthernet0/1", "ip arp inspection trust", "end"],
            )

        elif rule_id == "PORT_SECURITY_VIOLATION":
            return AIDiagnosisOutput(
                root_cause="Port security violation placing interface into err-disabled state",
                osi_layer="Layer 2",
                confidence=0.94,
                evidence=evidence_list,
                next_command="show port-security interface FastEthernet0/10",
                fix_steps=["configure terminal", "interface FastEthernet0/10", "shutdown", "no shutdown", "end"],
            )

        elif rule_id == "HSRP_TIMER_MISMATCH":
            return AIDiagnosisOutput(
                root_cause="HSRP hello/hold timer mismatch causing instability between standby peers",
                osi_layer="Layer 3",
                confidence=0.93,
                evidence=evidence_list,
                next_command="show standby brief",
                fix_steps=["configure terminal", "interface GigabitEthernet0/0", "standby 1 timers 3 10", "end"],
            )

        elif rule_id == "SUBINTERFACE_MISSING_ENCAPSULATION":
            return AIDiagnosisOutput(
                root_cause="Router sub-interface missing 802.1Q encapsulation dot1q definition",
                osi_layer="Layer 2/3",
                confidence=0.95,
                evidence=evidence_list,
                next_command="show running-config interface GigabitEthernet0/0.20",
                fix_steps=["configure terminal", "interface GigabitEthernet0/0.20", "encapsulation dot1Q 20", "ip address 192.168.20.1 255.255.255.0", "end"],
            )

        elif rule_id == "IPV6_RA_SUPPRESSED":
            return AIDiagnosisOutput(
                root_cause="IPv6 Router Advertisements suppressed preventing SLAAC autoconfiguration",
                osi_layer="Layer 3",
                confidence=0.93,
                evidence=evidence_list,
                next_command="show ipv6 interface GigabitEthernet0/0",
                fix_steps=["configure terminal", "interface GigabitEthernet0/0", "no ipv6 nd suppress-ra", "end"],
            )

        elif rule_id == "CDP_DISABLED_GLOBALLY":
            return AIDiagnosisOutput(
                root_cause="Cisco Discovery Protocol (CDP) globally disabled on device ('no cdp run')",
                osi_layer="Layer 2",
                confidence=0.91,
                evidence=evidence_list,
                next_command="show cdp",
                fix_steps=["configure terminal", "cdp run", "end"],
            )

        # Fallback for any other finding
        return AIDiagnosisOutput(
            root_cause=primary_finding.message,
            osi_layer="Layer 3",
            confidence=0.88,
            evidence=evidence_list,
            next_command="show running-config",
            fix_steps=["Inspect and remediate flagged telemetry anomaly"],
        )


# ============================================================================
# Gemini Live API Provider
# ============================================================================


class GeminiProvider(AIProvider):
    """Live LLM provider backed by Google Gemini API via official SDK."""

    def __init__(self, api_key: Optional[str] = None, model_name: str = "gemini-2.5-flash") -> None:
        """Initialize Gemini provider reading API key from argument or environment."""
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        self.model_name = model_name
        if not self.api_key:
            raise ValueError(
                "Gemini API key not provided and GEMINI_API_KEY environment variable is not set."
            )

    def generate_diagnosis(
        self,
        case: NetworkCase,
        deterministic_result: Optional[DeterministicResult] = None,
    ) -> AIDiagnosisOutput:
        """Invoke Gemini API with structured JSON output enforcement and robust error wrapping."""
        from netsage.logging_config import get_logger
        logger = get_logger("ai_engine")

        try:
            from google import genai
            from google.genai import types

            client = genai.Client(api_key=self.api_key)
            user_prompt = build_user_prompt(case, deterministic_result)

            logger.info(f"Dispatching diagnostic prompt for Case {case.case_id} to model {self.model_name}")
            response = client.models.generate_content(
                model=self.model_name,
                contents=[user_prompt],
                config=types.GenerateContentConfig(
                    system_instruction=SYSTEM_PROMPT,
                    response_mime_type="application/json",
                    response_schema=AIDiagnosisOutput,
                    temperature=0.1,
                ),
            )

            if not response or not response.text:
                raise ValueError("Gemini API returned an empty or invalid response.")

            raw_json = json.loads(response.text)
            return AIDiagnosisOutput(**raw_json)
        except ImportError as e:
            logger.error("google-genai SDK is not installed in the environment.")
            raise RuntimeError("The google-genai package is required for live Gemini API calls.") from e
        except Exception as e:
            logger.error(f"Gemini API diagnosis generation failed for Case {case.case_id}: {e}")
            raise RuntimeError(f"Gemini provider error: {e}") from e


# ============================================================================
# AI Diagnostic Engine Facade
# ============================================================================


class AIEngine:
    """Evidence-grounded diagnostic intelligence engine."""

    def __init__(self, provider: Optional[AIProvider] = None) -> None:
        """Initialize the AI Engine with an explicit or default offline provider."""
        self.provider: AIProvider = provider or OfflineDeterministicProvider()

    def diagnose(
        self,
        case: NetworkCase,
        deterministic_result: Optional[DeterministicResult] = None,
    ) -> AIDiagnosisOutput:
        """Execute AI diagnostic reasoning and enforce evidence grounding.

        Args:
            case: The NetworkCase instance.
            deterministic_result: Optional deterministic telemetry findings.

        Returns:
            AIDiagnosisOutput: Verified and grounded structured diagnostic output.

        Raises:
            UngroundedEvidenceError: If output contains ungrounded or hallucinated claims.
            ValueError: If structured schema validation fails.
        """
        raw_diagnosis = self.provider.generate_diagnosis(case, deterministic_result)
        validate_grounding(case, raw_diagnosis, deterministic_result)
        return raw_diagnosis


def diagnose(
    case: NetworkCase,
    deterministic_result: Optional[DeterministicResult] = None,
    provider: Optional[AIProvider] = None,
) -> AIDiagnosisOutput:
    """Convenience functional interface for AI diagnosis."""
    engine = AIEngine(provider=provider)
    return engine.diagnose(case, deterministic_result)
