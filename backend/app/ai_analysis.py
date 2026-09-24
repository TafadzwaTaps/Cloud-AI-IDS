import os
from openai import OpenAI

_client = None
# Configurable so you're not locked to one model string in code - bump
# this env var to gpt-5.5 (or whatever's current) without touching code.
DEFAULT_MODEL = os.getenv("OPENAI_MODEL", "gpt-5.4")


def get_openai_client() -> OpenAI:
    global _client
    if _client is not None:
        return _client
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError(
            "OPENAI_API_KEY is not set. Get one from platform.openai.com "
            "and set it as an environment variable to enable AI Threat Analysis."
        )
    _client = OpenAI(api_key=api_key)
    return _client


def build_prompt(flow: dict) -> str:
    """
    Builds the analysis prompt from a single flow's REAL detection data.
    Every value here is something the Random Forest classifier and
    CICFlowMeter feature extraction actually computed - the LLM's job
    is to explain and contextualize these numbers, not invent new ones.
    """
    top_preds = flow.get("top_predictions") or []
    top_preds_str = ", ".join(
        f"{p.get('label')} ({p.get('probability', 0) * 100:.1f}%)" for p in top_preds
    ) or "n/a"

    return f"""You are a SOC analyst assistant. Analyze this single network flow, \
which was flagged by a Random Forest multi-class intrusion detection classifier \
(NOT a signature-based or statistical-anomaly-baseline system - be precise about \
this in your analysis; the "confidence" figure below is the model's own predicted \
probability for its chosen class, not a separate anomaly score).

Detection:
- Predicted class: {flow.get('label', 'unknown')}
- Model confidence: {flow.get('confidence', 0) * 100:.1f}%
- Full probability breakdown (top classes): {top_preds_str}
- MITRE ATT&CK mapping (static reference table, not model-derived): {flow.get('mitre', 'n/a')}
- Severity: {flow.get('severity', 'unknown')}

Flow details (from CICFlowMeter feature extraction):
- Source: {flow.get('source', 'n/a')}
- Destination: {flow.get('dest', 'n/a')}
- Protocol/Port: {flow.get('proto', 'n/a')}/{flow.get('port', 'n/a')}
- Flow duration: {flow.get('flow_duration_ms', 'n/a')} ms
- Total packets: {flow.get('total_packets', 'n/a')}
- Flow rate: {flow.get('flow_packets_per_sec', 'n/a')} packets/s, {flow.get('flow_bytes_per_sec', 'n/a')} bytes/s
- SYN flag ratio: {flow.get('syn_flag_ratio', 'n/a')}

Write a concise SOC-style report in Markdown with exactly these sections:
## Root Cause Analysis
## Attack Signature
## Affected Assets
## Recommended Remediation

Recommended Remediation should be numbered steps, with example firewall/IDS rule
syntax where relevant. Be specific to the actual values above rather than generic.
If the source/destination IPs look like private/demo addresses (10.x.x.x
destinations, randomly-generated-looking source IPs), note plainly that this
appears to be simulated/demo traffic rather than a real incident. Keep the whole
response under 400 words."""


def generate_threat_analysis(flow: dict):
    """Returns (analysis_markdown, model_used)."""
    client = get_openai_client()
    model = DEFAULT_MODEL
    prompt = build_prompt(flow)

    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": "You are a precise, concise SOC analyst assistant."},
            {"role": "user", "content": prompt},
        ],
        max_tokens=900,
    )
    text = response.choices[0].message.content
    return text, model
