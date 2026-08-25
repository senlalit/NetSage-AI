"""Unit tests for NetSage AI deterministic diagnostic engine."""

import pytest
from netsage.case_loader import load_cases, get_case
from netsage.deterministic_engine import (
    DeterministicEngine,
    run_deterministic_checks,
    ALL_RULES,
)
from netsage.models import DeterministicFinding, DeterministicResult, NetworkCase


def test_rule_registry_count() -> None:
    """Verify that the engine registers all specialized deterministic rules."""
    engine = DeterministicEngine()
    assert len(engine.rules) == len(ALL_RULES)
    assert len(engine.rules) >= 28


def test_interface_admin_down_detection() -> None:
    """Verify detection of interface administratively down and shutdown states."""
    case_net001 = get_case("NET-001")
    assert case_net001 is not None
    result1 = run_deterministic_checks(case_net001)
    rule_ids1 = [f.rule_id for f in result1.findings]
    assert "INTERFACE_ADMIN_DOWN" in rule_ids1
    finding1 = next(f for f in result1.findings if f.rule_id == "INTERFACE_ADMIN_DOWN")
    assert "administratively down" in finding1.evidence

    case_net010 = get_case("NET-010")
    assert case_net010 is not None
    result2 = run_deterministic_checks(case_net010)
    rule_ids2 = [f.rule_id for f in result2.findings]
    assert "INTERFACE_ADMIN_DOWN" in rule_ids2
    finding2 = next(f for f in result2.findings if f.rule_id == "INTERFACE_ADMIN_DOWN")
    assert "shutdown" in finding2.evidence


def test_vlan_and_trunking_rules() -> None:
    """Verify detection of VLAN trunking and access configuration anomalies."""
    # NET-008: Trunk missing allowed VLAN
    case_net008 = get_case("NET-008")
    assert case_net008 is not None
    res_008 = run_deterministic_checks(case_net008)
    assert any(f.rule_id == "TRUNK_VLAN_NOT_ALLOWED" for f in res_008.findings)

    # NET-011: Inter-switch link in access mode
    case_net011 = get_case("NET-011")
    assert case_net011 is not None
    res_011 = run_deterministic_checks(case_net011)
    assert any(f.rule_id == "INTERSWITCH_ACCESS_MODE" for f in res_011.findings)

    # NET-013: Switchport access VLAN mismatch
    case_net013 = get_case("NET-013")
    assert case_net013 is not None
    res_013 = run_deterministic_checks(case_net013)
    assert any(f.rule_id == "ACCESS_VLAN_MISCONFIGURATION" for f in res_013.findings)

    # NET-019: Native VLAN mismatch
    case_net019 = get_case("NET-019")
    assert case_net019 is not None
    res_019 = run_deterministic_checks(case_net019)
    assert any(f.rule_id == "NATIVE_VLAN_MISMATCH" for f in res_019.findings)


def test_nat_rules() -> None:
    """Verify detection of NAT overload and interface direction anomalies."""
    # NET-006: NAT missing overload
    case_net006 = get_case("NET-006")
    assert case_net006 is not None
    res_006 = run_deterministic_checks(case_net006)
    assert any(f.rule_id == "NAT_MISSING_OVERLOAD" for f in res_006.findings)

    # NET-017: NAT missing inside/outside interface
    case_net017 = get_case("NET-017")
    assert case_net017 is not None
    res_017 = run_deterministic_checks(case_net017)
    assert any(f.rule_id == "NAT_MISSING_INTERFACE_DIRECTION" for f in res_017.findings)


def test_acl_rules() -> None:
    """Verify detection of ACL deny, overly permissive, and missing port rules."""
    # NET-005: Explicit deny
    case_net005 = get_case("NET-005")
    assert case_net005 is not None
    res_005 = run_deterministic_checks(case_net005)
    assert any(f.rule_id == "ACL_EXPLICIT_DENY" for f in res_005.findings)

    # NET-007: Overly permissive permit any
    case_net007 = get_case("NET-007")
    assert case_net007 is not None
    res_007 = run_deterministic_checks(case_net007)
    assert any(f.rule_id == "ACL_OVERLY_PERMISSIVE" for f in res_007.findings)

    # NET-016: Missing FTP port
    case_net016 = get_case("NET-016")
    assert case_net016 is not None
    res_016 = run_deterministic_checks(case_net016)
    assert any(f.rule_id == "ACL_MISSING_REQUIRED_PORT" for f in res_016.findings)

    # NET-022: Missing HTTPS port 443
    case_net022 = get_case("NET-022")
    assert case_net022 is not None
    res_022 = run_deterministic_checks(case_net022)
    assert any(f.rule_id == "ACL_MISSING_REQUIRED_PORT" for f in res_022.findings)


def test_routing_and_ospf_rules() -> None:
    """Verify detection of OSPF timer mismatches, passive interfaces, and static route nexthop issues."""
    # NET-004: OSPF timer mismatch
    case_net004 = get_case("NET-004")
    assert case_net004 is not None
    res_004 = run_deterministic_checks(case_net004)
    assert any(f.rule_id == "OSPF_TIMER_MISMATCH" for f in res_004.findings)

    # NET-012: OSPF passive interface on transit link
    case_net012 = get_case("NET-012")
    assert case_net012 is not None
    res_012 = run_deterministic_checks(case_net012)
    assert any(f.rule_id == "OSPF_PASSIVE_INTERFACE_ACTIVE_LINK" for f in res_012.findings)

    # NET-015: Static route unreachable next-hop
    case_net015 = get_case("NET-015")
    assert case_net015 is not None
    res_015 = run_deterministic_checks(case_net015)
    assert any(f.rule_id == "STATIC_ROUTE_NEXT_HOP_UNREACHABLE" for f in res_015.findings)

    # NET-021: OSPF redistribution missing subnets
    case_net021 = get_case("NET-021")
    assert case_net021 is not None
    res_021 = run_deterministic_checks(case_net021)
    assert any(f.rule_id == "OSPF_REDISTRIBUTE_MISSING_SUBNETS" for f in res_021.findings)


def test_dhcp_and_dns_rules() -> None:
    """Verify detection of DHCP pool exhaustion, helper-address omission, and DNS disabled."""
    # NET-002: DHCP pool exhaustion
    case_net002 = get_case("NET-002")
    assert case_net002 is not None
    res_002 = run_deterministic_checks(case_net002)
    assert any(f.rule_id == "DHCP_POOL_EXHAUSTED" for f in res_002.findings)

    # NET-003: DNS disabled
    case_net003 = get_case("NET-003")
    assert case_net003 is not None
    res_003 = run_deterministic_checks(case_net003)
    assert any(f.rule_id == "DNS_DOMAIN_LOOKUP_DISABLED" for f in res_003.findings)

    # NET-014: DHCP missing helper address
    case_net014 = get_case("NET-014")
    assert case_net014 is not None
    res_014 = run_deterministic_checks(case_net014)
    assert any(f.rule_id == "DHCP_MISSING_HELPER_ADDRESS" for f in res_014.findings)


def test_all_30_benchmark_cases_produce_findings() -> None:
    """Verify that every single benchmark case in cases.csv triggers deterministic telemetry findings."""
    cases = load_cases()
    assert len(cases) == 30

    engine = DeterministicEngine()
    for case in cases:
        result = engine.analyze_case(case)
        assert result.rules_checked == len(ALL_RULES)
        assert len(result.findings) >= 1, f"Case {case.case_id} produced no deterministic findings."

        # Verify evidence grounding for every finding
        combined_text = f"{case.show_outputs} {case.topology_note} {case.symptom}".lower()
        for finding in result.findings:
            assert finding.evidence, f"Empty evidence for {case.case_id} ({finding.rule_id})"
            # Key tokens in evidence must be present in the source input
            evidence_sample = finding.evidence.lower()[:20]
            assert evidence_sample in combined_text, (
                f"Evidence '{finding.evidence}' for case {case.case_id} not grounded in input text."
            )


def test_determinism_and_reproducibility() -> None:
    """Verify that running the engine multiple times on the same input produces identical output."""
    case = get_case("NET-001")
    assert case is not None
    engine = DeterministicEngine()

    run1 = engine.analyze_case(case)
    run2 = engine.analyze_case(case)

    assert run1.rules_checked == run2.rules_checked
    assert len(run1.findings) == len(run2.findings)
    for f1, f2 in zip(run1.findings, run2.findings):
        assert f1.rule_id == f2.rule_id
        assert f1.status == f2.status
        assert f1.evidence == f2.evidence
        assert f1.message == f2.message


def test_clean_input_produces_no_false_positives() -> None:
    """Verify that clean, healthy Cisco show outputs do not trigger false positive findings."""
    clean_show = (
        "GigabitEthernet0/0 is up, line protocol is up\n"
        "ip address 192.168.1.1 255.255.255.0\n"
        "Switchport trunk allowed vlan 10,20,30\n"
        "router ospf 1\n"
        " network 192.168.1.0 0.0.0.255 area 0\n"
    )
    result = run_deterministic_checks(clean_show)
    assert result.rules_checked == len(ALL_RULES)
    assert len(result.findings) == 0


def test_empty_input_handled_gracefully() -> None:
    """Verify that completely empty input strings return zero findings without errors."""
    result = run_deterministic_checks("", topology_note="", symptom="")
    assert result.rules_checked == len(ALL_RULES)
    assert len(result.findings) == 0
