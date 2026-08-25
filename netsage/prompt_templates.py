"""Prompt templates and prompt assembly for NetSage AI diagnostic reasoning."""

import json
from typing import Optional
from netsage.models import DeterministicResult, NetworkCase

SYSTEM_PROMPT = """You are NetSage AI, an expert Cisco and Packet Tracer network troubleshooting intelligence assistant.

Your role is to analyze observable network symptoms, topology context, Cisco show-command outputs, and deterministic telemetry findings to produce an accurate, evidence-grounded diagnosis and remediation plan.

CRITICAL SAFETY & GROUNDING RULES:
1. STRICT EVIDENCE GROUNDING: You MUST base your diagnosis ONLY on the explicitly supplied symptom, topology notes, show command outputs, and deterministic telemetry findings.
2. ZERO HALLUCINATION: You MUST NOT invent network evidence, hallucinate hidden configurations, or assume states not present in the supplied telemetry.
3. ADVISORY ONLY: You do NOT have the ability to execute commands on live devices. All remediation steps are recommendations for a human network engineer.
4. NEXT COMMAND: Provide a single Cisco IOS verification command to confirm the state or remediation.
5. JSON CONTRACT: You MUST output ONLY a valid JSON object strictly matching the schema below:

```json
{
  "root_cause": "Precise identification of the technical network fault",
  "osi_layer": "One of: Layer 1, Layer 2, Layer 2/3, Layer 3, Layer 3/4, Layer 4, Layer 5, Layer 6, Layer 7",
  "confidence": 0.95,
  "evidence": [
    "Verbatim or directly supported quote from symptom, topology, or show-command output"
  ],
  "next_command": "Single Cisco IOS verification command (e.g. show ip interface brief)",
  "fix_steps": [
    "Sequential Cisco IOS configuration command (e.g. interface Gi0/0.10, no shutdown)"
  ]
}
```
"""


def build_user_prompt(case: NetworkCase, deterministic_result: Optional[DeterministicResult] = None) -> str:
    """Construct the user prompt for AI diagnosis without exposing expected_fault.

    Args:
        case: The NetworkCase instance (symptom, topology_note, show_outputs).
        deterministic_result: Optional result from the deterministic rules engine.

    Returns:
        str: Formatted user prompt text.
    """
    prompt_lines = [
        f"=== NETWORK TROUBLESHOOTING CASE: {case.case_id} ===",
        "",
        "--- OBSERVABLE SYMPTOM ---",
        case.symptom,
        "",
        "--- TOPOLOGY CONTEXT ---",
        case.topology_note,
        "",
        "--- CISCO SHOW COMMAND OUTPUTS ---",
        case.show_outputs,
        "",
    ]

    if deterministic_result and deterministic_result.findings:
        prompt_lines.append("--- DETERMINISTIC TELEMETRY FINDINGS ---")
        for idx, finding in enumerate(deterministic_result.findings, start=1):
            prompt_lines.append(
                f"[{idx}] Rule: {finding.rule_id} | Status: {finding.status} | "
                f"Evidence: \"{finding.evidence}\" | Finding: {finding.message}"
            )
        prompt_lines.append("")
    else:
        prompt_lines.append("--- DETERMINISTIC TELEMETRY FINDINGS ---")
        prompt_lines.append("No automated rule anomalies flagged.")
        prompt_lines.append("")

    prompt_lines.append(
        "Analyze the telemetry above and produce the structured JSON diagnosis adhering strictly to the required schema."
    )

    return "\n".join(prompt_lines)
