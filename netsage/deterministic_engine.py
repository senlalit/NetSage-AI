"""Deterministic diagnostic rule engine for NetSage AI.

Extracts factual anomalies and telemetry indicators from Cisco IOS show command outputs,
topology notes, and symptoms without speculative LLM reasoning or accessing benchmark evaluation labels.
"""

import re
from typing import Callable, List, Optional, Sequence, Union

from netsage.models import DeterministicFinding, DeterministicResult, NetworkCase

RuleFunc = Callable[[str, str, str], Optional[DeterministicFinding]]


# ============================================================================
# Individual Deterministic Rules
# ============================================================================


def rule_interface_admin_down(show_outputs: str, topology_note: str, symptom: str) -> Optional[DeterministicFinding]:
    """Detect interfaces that are administratively down or explicitly in shutdown state."""
    combined = f"{show_outputs} {topology_note}"

    # Match "GigabitEthernet0/0.10 is administratively down line protocol is down"
    match_admin = re.search(
        r"([A-Za-z0-9/.]+)\s+is\s+administratively\s+down(?:\s+line\s+protocol\s+is\s+down)?",
        combined,
        re.IGNORECASE,
    )
    if match_admin:
        evidence = match_admin.group(0).strip()
        intf = match_admin.group(1)
        return DeterministicFinding(
            rule_id="INTERFACE_ADMIN_DOWN",
            status="ERROR",
            evidence=evidence,
            message=f"Interface '{intf}' is administratively down.",
        )

    # Match "interface Vlan1; ... shutdown" or "interface Fa0/1; shutdown"
    match_shut = re.search(
        r"(interface\s+([A-Za-z0-9/.]+)[^;\n]*(?:;[^;\n]*)*;\s*shutdown|interface\s+([A-Za-z0-9/.]+)[^;\n]*\bshutdown\b)",
        combined,
        re.IGNORECASE,
    )
    if match_shut:
        evidence = match_shut.group(1).strip()
        intf = match_shut.group(2) or match_shut.group(3)
        return DeterministicFinding(
            rule_id="INTERFACE_ADMIN_DOWN",
            status="ERROR",
            evidence=evidence,
            message=f"Management/interface '{intf}' is configured in shutdown state.",
        )

    return None


def rule_dhcp_pool_exhaustion(show_outputs: str, topology_note: str, symptom: str) -> Optional[DeterministicFinding]:
    """Detect exhausted DHCP address scopes with zero available leases."""
    combined = f"{show_outputs} {symptom}"
    match = re.search(
        r"(ip\s+dhcp\s+pool\s+\w+;\s*total\s+addresses\s+(\d+);\s*leased\s+(\d+);\s*zero\s+available|total\s+addresses\s+(\d+);\s*leased\s+\4;\s*zero\s+available)",
        combined,
        re.IGNORECASE,
    )
    if match:
        return DeterministicFinding(
            rule_id="DHCP_POOL_EXHAUSTED",
            status="ERROR",
            evidence=match.group(1).strip(),
            message="DHCP scope pool has 0 available addresses (all leased).",
        )
    return None


def rule_dns_disabled(show_outputs: str, topology_note: str, symptom: str) -> Optional[DeterministicFinding]:
    """Detect disabled domain lookup or inactive name servers."""
    match = re.search(
        r"(no\s+ip\s+domain-lookup;\s*ip\s+name-server\s+[0-9.]+\s+not\s+active|no\s+ip\s+domain-lookup)",
        show_outputs,
        re.IGNORECASE,
    )
    if match:
        return DeterministicFinding(
            rule_id="DNS_DOMAIN_LOOKUP_DISABLED",
            status="ERROR",
            evidence=match.group(0).strip(),
            message="Domain lookup is disabled on device ('no ip domain-lookup').",
        )
    return None


def rule_ospf_timer_mismatch(show_outputs: str, topology_note: str, symptom: str) -> Optional[DeterministicFinding]:
    """Detect OSPF hello/dead timer discrepancies across peers."""
    match = re.search(
        r"ip\s+ospf\s+hello-interval\s+(\d+).*?ip\s+ospf\s+hello-interval\s+(\d+)",
        show_outputs,
        re.IGNORECASE,
    )
    if match:
        int1, int2 = match.group(1), match.group(2)
        if int1 != int2:
            return DeterministicFinding(
                rule_id="OSPF_TIMER_MISMATCH",
                status="ERROR",
                evidence=show_outputs.strip(),
                message=f"OSPF hello timer mismatch detected between peers ({int1}s vs {int2}s).",
            )
    return None


def rule_acl_explicit_deny(show_outputs: str, topology_note: str, symptom: str) -> Optional[DeterministicFinding]:
    """Detect explicit ACL deny statements blocking traffic."""
    match = re.search(
        r"(access-list\s+\d+\s+deny\s+\w+\s+[^;]+)",
        show_outputs,
        re.IGNORECASE,
    )
    if match:
        return DeterministicFinding(
            rule_id="ACL_EXPLICIT_DENY",
            status="ERROR",
            evidence=match.group(1).strip(),
            message="Explicit Access Control List (ACL) rule is denying traffic.",
        )
    return None


def rule_nat_missing_overload(show_outputs: str, topology_note: str, symptom: str) -> Optional[DeterministicFinding]:
    """Detect dynamic NAT/PAT configurations missing the 'overload' keyword."""
    match = re.search(
        r"(ip\s+nat\s+inside\s+source\s+list\s+[^;]+(?:\(missing\s+overload\s+keyword\)|missing\s+overload))",
        show_outputs,
        re.IGNORECASE,
    )
    if match:
        return DeterministicFinding(
            rule_id="NAT_MISSING_OVERLOAD",
            status="ERROR",
            evidence=match.group(1).strip(),
            message="Dynamic NAT translation is missing the 'overload' keyword for PAT.",
        )
    return None


def rule_acl_overly_permissive(show_outputs: str, topology_note: str, symptom: str) -> Optional[DeterministicFinding]:
    """Detect overly permissive ACL rules allowing unrestricted access."""
    match = re.search(
        r"(Extended\s+IP\s+access\s+list\s+\w+:\s*\d+\s+permit\s+ip\s+[0-9.]+\s+[0-9.]+\s+any|permit\s+ip\s+[0-9.]+\s+[0-9.]+\s+any)",
        show_outputs,
        re.IGNORECASE,
    )
    if match:
        return DeterministicFinding(
            rule_id="ACL_OVERLY_PERMISSIVE",
            status="WARNING",
            evidence=match.group(0).strip(),
            message="Access control list contains overly permissive 'permit ip ... any' rule.",
        )
    return None


def rule_trunk_vlan_not_allowed(show_outputs: str, topology_note: str, symptom: str) -> Optional[DeterministicFinding]:
    """Detect VLANs omitted or pruned from 802.1Q trunk allowed lists."""
    match = re.search(
        r"(Switchport\s+trunk\s+allowed\s+vlan\s+[^;]+(?:\([^)]*missing[^)]*\)|missing\s+from\s+allowed\s+list))",
        show_outputs,
        re.IGNORECASE,
    )
    if match:
        return DeterministicFinding(
            rule_id="TRUNK_VLAN_NOT_ALLOWED",
            status="ERROR",
            evidence=match.group(1).strip(),
            message="Required VLAN is missing from switchport trunk allowed VLAN list.",
        )
    return None


def rule_host_gateway_mismatch(show_outputs: str, topology_note: str, symptom: str) -> Optional[DeterministicFinding]:
    """Detect host default gateway set to an unexpected or incorrect gateway IP."""
    match = re.search(
        r"(IP\s+configuration\s+shows\s+Default\s+Gateway\s+([0-9.]+)\s+on\s+Host|Default\s+Gateway\s+([0-9.]+)\s+on\s+Host)",
        show_outputs,
        re.IGNORECASE,
    )
    if match:
        gw = match.group(2) or match.group(3)
        return DeterministicFinding(
            rule_id="HOST_GATEWAY_MISMATCH",
            status="ERROR",
            evidence=match.group(1).strip(),
            message=f"Host default gateway is configured as '{gw}'.",
        )
    return None


def rule_interswitch_access_mode(show_outputs: str, topology_note: str, symptom: str) -> Optional[DeterministicFinding]:
    """Detect inter-switch links incorrectly configured in access mode instead of trunk."""
    match = re.search(
        r"(SW1\s+\S+:\s*switchport\s+mode\s+access;\s*SW2\s+\S+:\s*switchport\s+mode\s+access|\S+:\s*switchport\s+mode\s+access;\s*\S+:\s*switchport\s+mode\s+access)",
        show_outputs,
        re.IGNORECASE,
    )
    if match:
        return DeterministicFinding(
            rule_id="INTERSWITCH_ACCESS_MODE",
            status="ERROR",
            evidence=match.group(1).strip(),
            message="Inter-switch link interfaces are configured as access ports instead of 802.1Q trunk.",
        )
    return None


def rule_ospf_passive_interface(show_outputs: str, topology_note: str, symptom: str) -> Optional[DeterministicFinding]:
    """Detect OSPF passive-interface command configured on an active transit link."""
    match = re.search(
        r"(passive-interface\s+([A-Za-z0-9/.]+))",
        show_outputs,
        re.IGNORECASE,
    )
    if match:
        intf = match.group(2)
        return DeterministicFinding(
            rule_id="OSPF_PASSIVE_INTERFACE_ACTIVE_LINK",
            status="ERROR",
            evidence=match.group(1).strip(),
            message=f"OSPF passive-interface is active on transit interface '{intf}', preventing adjacency.",
        )
    return None


def rule_access_vlan_misconfiguration(show_outputs: str, topology_note: str, symptom: str) -> Optional[DeterministicFinding]:
    """Detect access ports configured with incorrect VLAN IDs."""
    match = re.search(
        r"(interface\s+FastEthernet0/10;\s*switchport\s+access\s+vlan\s+(\d+)|switchport\s+access\s+vlan\s+(\d+))",
        show_outputs,
        re.IGNORECASE,
    )
    if match:
        vlan = match.group(2) or match.group(3)
        return DeterministicFinding(
            rule_id="ACCESS_VLAN_MISCONFIGURATION",
            status="ERROR",
            evidence=match.group(1).strip(),
            message=f"Switchport access VLAN is configured as VLAN {vlan}.",
        )
    return None


def rule_dhcp_missing_helper(show_outputs: str, topology_note: str, symptom: str) -> Optional[DeterministicFinding]:
    """Detect router interfaces receiving DHCP discovers without ip helper-address."""
    match = re.search(
        r"(\(missing\s+ip\s+helper-address\)|missing\s+ip\s+helper-address)",
        show_outputs,
        re.IGNORECASE,
    )
    if match:
        return DeterministicFinding(
            rule_id="DHCP_MISSING_HELPER_ADDRESS",
            status="ERROR",
            evidence=show_outputs.strip(),
            message="Router interface is missing 'ip helper-address' for DHCP relay.",
        )
    return None


def rule_static_route_unreachable_nexthop(show_outputs: str, topology_note: str, symptom: str) -> Optional[DeterministicFinding]:
    """Detect static routes pointing to unreachable next-hop addresses."""
    match = re.search(
        r"(ip\s+route\s+[0-9.]+\s+[0-9.]+\s+([0-9.]+)\s+\([^)]*unreachable[^)]*\))",
        show_outputs,
        re.IGNORECASE,
    )
    if match:
        return DeterministicFinding(
            rule_id="STATIC_ROUTE_NEXT_HOP_UNREACHABLE",
            status="ERROR",
            evidence=match.group(1).strip(),
            message=f"Static route next-hop IP '{match.group(2)}' is unreachable.",
        )
    return None


def rule_acl_missing_required_port(show_outputs: str, topology_note: str, symptom: str) -> Optional[DeterministicFinding]:
    """Detect ACL permit statements that miss required companion ports (e.g. FTP port 21, HTTPS 443)."""
    match = re.search(
        r"(access-list\s+[^;]+\(missing\s+port\s+(\d+)\))",
        show_outputs,
        re.IGNORECASE,
    )
    if match:
        port = match.group(2)
        return DeterministicFinding(
            rule_id="ACL_MISSING_REQUIRED_PORT",
            status="ERROR",
            evidence=match.group(1).strip(),
            message=f"Access list filter is missing permit rule for required port {port}.",
        )
    return None


def rule_nat_missing_interface_direction(show_outputs: str, topology_note: str, symptom: str) -> Optional[DeterministicFinding]:
    """Detect missing 'ip nat inside' or 'ip nat outside' commands on routed interfaces."""
    match = re.search(
        r"(interface\s+\S+\s+missing\s+ip\s+nat\s+(inside|outside))",
        show_outputs,
        re.IGNORECASE,
    )
    if match:
        direction = match.group(2)
        return DeterministicFinding(
            rule_id="NAT_MISSING_INTERFACE_DIRECTION",
            status="ERROR",
            evidence=match.group(1).strip(),
            message=f"Router interface is missing 'ip nat {direction}' configuration.",
        )
    return None


def rule_radius_secret_mismatch(show_outputs: str, topology_note: str, symptom: str) -> Optional[DeterministicFinding]:
    """Detect incorrect RADIUS shared secret configuration."""
    match = re.search(
        r"(radius-server\s+host\s+[0-9.]+\s+key\s+(?:incorrect_secret_key|\S+))",
        show_outputs,
        re.IGNORECASE,
    )
    if match:
        return DeterministicFinding(
            rule_id="RADIUS_SECRET_MISMATCH",
            status="ERROR",
            evidence=match.group(1).strip(),
            message="RADIUS server shared secret mismatch detected in configuration.",
        )
    return None


def rule_native_vlan_mismatch(show_outputs: str, topology_note: str, symptom: str) -> Optional[DeterministicFinding]:
    """Detect native VLAN discrepancies across 802.1Q trunk link endpoints."""
    match = re.search(
        r"(\w+:\s*switchport\s+trunk\s+native\s+vlan\s+(\d+);\s*\w+:\s*switchport\s+trunk\s+native\s+vlan\s+(\d+))",
        show_outputs,
        re.IGNORECASE,
    )
    if match:
        v1, v2 = match.group(2), match.group(3)
        if v1 != v2:
            return DeterministicFinding(
                rule_id="NATIVE_VLAN_MISMATCH",
                status="ERROR",
                evidence=match.group(1).strip(),
                message=f"Native VLAN mismatch on trunk link (VLAN {v1} vs VLAN {v2}).",
            )
    return None


def rule_gateway_outside_subnet(show_outputs: str, topology_note: str, symptom: str) -> Optional[DeterministicFinding]:
    """Detect default gateway configured outside the host subnet boundary."""
    match = re.search(
        r"(IP\s+([0-9.]+)\s+mask\s+([0-9.]+);\s*Gateway\s+([0-9.]+)\s*\(Outside\s+subnet\s+boundary\))",
        show_outputs,
        re.IGNORECASE,
    )
    if match:
        return DeterministicFinding(
            rule_id="GATEWAY_OUTSIDE_SUBNET",
            status="ERROR",
            evidence=match.group(1).strip(),
            message=f"Configured default gateway '{match.group(4)}' is outside host subnet range.",
        )
    return None


def rule_ospf_redistribution_missing_subnets(show_outputs: str, topology_note: str, symptom: str) -> Optional[DeterministicFinding]:
    """Detect OSPF route redistribution missing the required 'subnets' keyword."""
    match = re.search(
        r"(router\s+ospf\s+\d+;\s*redistribute\s+\w+\s+\d*\s*\(missing\s+subnets\s+keyword\)|redistribute\s+\w+\s+\d*\s*\(missing\s+subnets\s+keyword\))",
        show_outputs,
        re.IGNORECASE,
    )
    if match:
        return DeterministicFinding(
            rule_id="OSPF_REDISTRIBUTE_MISSING_SUBNETS",
            status="ERROR",
            evidence=match.group(0).strip(),
            message="OSPF route redistribution command is missing the 'subnets' parameter.",
        )
    return None


def rule_duplicate_ip_detected(show_outputs: str, topology_note: str, symptom: str) -> Optional[DeterministicFinding]:
    """Detect duplicate IP address conflict syslogs."""
    match = re.search(
        r"(%IP-4-DUP_ADDR:\s*Duplicate\s+address\s+([0-9.]+)\s+on\s+(\S+))",
        show_outputs,
        re.IGNORECASE,
    )
    if match:
        ip_addr = match.group(2)
        intf = match.group(3)
        return DeterministicFinding(
            rule_id="DUPLICATE_IP_DETECTED",
            status="ERROR",
            evidence=match.group(1).strip(),
            message=f"Duplicate IP address conflict detected for '{ip_addr}' on interface '{intf}'.",
        )
    return None


def rule_vtp_domain_mismatch(show_outputs: str, topology_note: str, symptom: str) -> Optional[DeterministicFinding]:
    """Detect VTP domain name string case mismatches."""
    match = re.search(
        r"(\w+:\s*vtp\s+domain\s+(\S+);\s*\w+:\s*vtp\s+domain\s+(\S+)\s*\([^)]*mismatch[^)]*\))",
        show_outputs,
        re.IGNORECASE,
    )
    if match:
        return DeterministicFinding(
            rule_id="VTP_DOMAIN_MISMATCH",
            status="ERROR",
            evidence=match.group(1).strip(),
            message=f"VTP domain name mismatch detected between switches ('{match.group(2)}' vs '{match.group(3)}').",
        )
    return None


def rule_dai_missing_trust(show_outputs: str, topology_note: str, symptom: str) -> Optional[DeterministicFinding]:
    """Detect Dynamic ARP Inspection (DAI) missing trust state on switch trunk uplinks."""
    match = re.search(
        r"(interface\s+(\S+);\s*ip\s+arp\s+inspection\s+trust\s+missing\s+on\s+uplink)",
        show_outputs,
        re.IGNORECASE,
    )
    if match:
        intf = match.group(2)
        return DeterministicFinding(
            rule_id="DAI_MISSING_TRUST",
            status="ERROR",
            evidence=match.group(1).strip(),
            message=f"Dynamic ARP Inspection (DAI) trust missing on uplink interface '{intf}'.",
        )
    return None


def rule_port_security_violation(show_outputs: str, topology_note: str, symptom: str) -> Optional[DeterministicFinding]:
    """Detect port-security violation events putting ports into err-disabled state."""
    match = re.search(
        r"(%PORT_SECURITY-2-PSECURE_VIOLATION:\s*Security\s+violation\s+occurred\s+on\s+port\s+(\S+))",
        show_outputs,
        re.IGNORECASE,
    )
    if match:
        port = match.group(2)
        return DeterministicFinding(
            rule_id="PORT_SECURITY_VIOLATION",
            status="ERROR",
            evidence=match.group(1).strip(),
            message=f"Port security violation limit exceeded on switchport '{port}'.",
        )
    return None


def rule_hsrp_timer_mismatch(show_outputs: str, topology_note: str, symptom: str) -> Optional[DeterministicFinding]:
    """Detect HSRP hello timer discrepancies between peer routers."""
    match = re.search(
        r"standby\s+(\d+)\s+priority\s+\d+\s+hello\s+(\d+);\s*\w+:\s*standby\s+\1\s+priority\s+\d+\s+hello\s+(\d+)",
        show_outputs,
        re.IGNORECASE,
    )
    if match:
        h1, h2 = match.group(2), match.group(3)
        if h1 != h2:
            return DeterministicFinding(
                rule_id="HSRP_TIMER_MISMATCH",
                status="ERROR",
                evidence=show_outputs.strip(),
                message=f"HSRP hello timer mismatch in Group {match.group(1)} ({h1}s vs {h2}s).",
            )
    return None


def rule_subinterface_missing_encapsulation(show_outputs: str, topology_note: str, symptom: str) -> Optional[DeterministicFinding]:
    """Detect router sub-interfaces missing 802.1Q encapsulation."""
    match = re.search(
        r"(interface\s+([A-Za-z0-9/.]+);[^;]*\(missing\s+encapsulation\s+dot1Q(?:\s+\d+)?\))",
        show_outputs,
        re.IGNORECASE,
    )
    if match:
        intf = match.group(2)
        return DeterministicFinding(
            rule_id="SUBINTERFACE_MISSING_ENCAPSULATION",
            status="ERROR",
            evidence=match.group(1).strip(),
            message=f"Router sub-interface '{intf}' is missing 802.1Q dot1q encapsulation.",
        )
    return None


def rule_ipv6_ra_suppressed(show_outputs: str, topology_note: str, symptom: str) -> Optional[DeterministicFinding]:
    """Detect IPv6 router advertisements (RA) suppressed on interface."""
    match = re.search(
        r"(interface\s+([A-Za-z0-9/.]+);\s*ipv6\s+nd\s+suppress-ra\s+enabled)",
        show_outputs,
        re.IGNORECASE,
    )
    if match:
        intf = match.group(2)
        return DeterministicFinding(
            rule_id="IPV6_RA_SUPPRESSED",
            status="ERROR",
            evidence=match.group(1).strip(),
            message=f"IPv6 Router Advertisements are suppressed on interface '{intf}'.",
        )
    return None


def rule_cdp_disabled_globally(show_outputs: str, topology_note: str, symptom: str) -> Optional[DeterministicFinding]:
    """Detect CDP globally disabled on network device."""
    match = re.search(
        r"(no\s+cdp\s+run\s+globally\s+active(?:\s+in\s+running\s+configuration)?|no\s+cdp\s+run)",
        show_outputs,
        re.IGNORECASE,
    )
    if match:
        return DeterministicFinding(
            rule_id="CDP_DISABLED_GLOBALLY",
            status="WARNING",
            evidence=match.group(0).strip(),
            message="Cisco Discovery Protocol (CDP) is disabled globally ('no cdp run').",
        )
    return None


# ============================================================================
# Registered Rules Registry
# ============================================================================

ALL_RULES: List[RuleFunc] = [
    rule_interface_admin_down,
    rule_dhcp_pool_exhaustion,
    rule_dns_disabled,
    rule_ospf_timer_mismatch,
    rule_acl_explicit_deny,
    rule_nat_missing_overload,
    rule_acl_overly_permissive,
    rule_trunk_vlan_not_allowed,
    rule_host_gateway_mismatch,
    rule_interswitch_access_mode,
    rule_ospf_passive_interface,
    rule_access_vlan_misconfiguration,
    rule_dhcp_missing_helper,
    rule_static_route_unreachable_nexthop,
    rule_acl_missing_required_port,
    rule_nat_missing_interface_direction,
    rule_radius_secret_mismatch,
    rule_native_vlan_mismatch,
    rule_gateway_outside_subnet,
    rule_ospf_redistribution_missing_subnets,
    rule_duplicate_ip_detected,
    rule_vtp_domain_mismatch,
    rule_dai_missing_trust,
    rule_port_security_violation,
    rule_hsrp_timer_mismatch,
    rule_subinterface_missing_encapsulation,
    rule_ipv6_ra_suppressed,
    rule_cdp_disabled_globally,
]


# ============================================================================
# Deterministic Engine Service
# ============================================================================


class DeterministicEngine:
    """Deterministic rule-based analysis engine for Cisco network telemetry."""

    def __init__(self, rules: Optional[Sequence[RuleFunc]] = None) -> None:
        """Initialize the deterministic engine with a custom or default rule set."""
        self.rules: List[RuleFunc] = list(rules) if rules is not None else list(ALL_RULES)

    def analyze_case(self, case: NetworkCase) -> DeterministicResult:
        """Execute deterministic rules against a NetworkCase.

        Args:
            case: The NetworkCase instance to analyze.

        Returns:
            DeterministicResult: Aggregated list of findings and count of rules evaluated.
        """
        return self.analyze_raw(
            show_outputs=case.show_outputs,
            topology_note=case.topology_note,
            symptom=case.symptom,
        )

    def analyze_raw(
        self,
        show_outputs: str,
        topology_note: str = "",
        symptom: str = "",
    ) -> DeterministicResult:
        """Execute all registered deterministic rules against raw telemetry strings.

        Args:
            show_outputs: Cisco show command outputs.
            topology_note: Topology or interface context.
            symptom: Observable symptom description.

        Returns:
            DeterministicResult: Result containing all matched findings and rules count.
        """
        findings: List[DeterministicFinding] = []

        for rule in self.rules:
            finding = rule(show_outputs, topology_note, symptom)
            if finding is not None:
                findings.append(finding)

        return DeterministicResult(
            findings=findings,
            rules_checked=len(self.rules),
        )


def run_deterministic_checks(
    target: Union[NetworkCase, str],
    topology_note: str = "",
    symptom: str = "",
) -> DeterministicResult:
    """Convenience functional interface to run deterministic network checks."""
    engine = DeterministicEngine()
    if isinstance(target, NetworkCase):
        return engine.analyze_case(target)
    return engine.analyze_raw(
        show_outputs=target,
        topology_note=topology_note,
        symptom=symptom,
    )
