import os
from google import genai
from google.genai import types

_client = None
# Configurable so you're not locked to one model string in code.
# NOTE: deliberately pinned to a real, versioned model id rather than
# the "gemini-flash-latest" alias - that alias was resolving to the
# now-discontinued gemini-2.0-flash and threw a confusing 404 NOT_FOUND
# ("This model models/gemini-2.0-flash is no longer available") on
# every /analyze call. Bump this env var when you want to move to a
# newer model (e.g. gemini-3.5-flash), but always use a real, current
# model id - check aistudio.google.com/models for what's live.
DEFAULT_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

SYSTEM_INSTRUCTION = "You are a precise, concise SOC analyst assistant."


def get_gemini_client():
    global _client
    if _client is not None:
        return _client
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError(
            "GEMINI_API_KEY is not set. Get a free key from Google AI Studio "
            "(aistudio.google.com/apikey) and set it as an environment variable "
            "to enable AI Threat Analysis."
        )
    _client = genai.Client(api_key=api_key)
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
    client = get_gemini_client()
    model = DEFAULT_MODEL
    prompt = build_prompt(flow)

    try:
        response = client.models.generate_content(
            model=model,
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_INSTRUCTION,
                max_output_tokens=900,
            ),
        )
    except Exception as e:
        # Surface the real Gemini error (bad model id, quota, auth, etc.)
        # instead of letting a raw SDK exception bubble up as an opaque 502.
        raise RuntimeError(f"Gemini request failed ({model}): {e}") from e

    # response.text raises if the model returned no usable content (blocked
    # by a safety filter, hit MAX_TOKENS with nothing generated, etc.) -
    # handle that explicitly instead of crashing with a bare 502.
    candidates = getattr(response, "candidates", None) or []
    if not candidates or not getattr(candidates[0], "content", None):
        finish_reason = getattr(candidates[0], "finish_reason", "unknown") if candidates else "no candidates"
        raise RuntimeError(
            f"Gemini returned no content for this flow (finish_reason={finish_reason}). "
            "This can happen if the flow data triggered a safety filter, or the "
            "response was truncated. Try again, or inspect a different flow."
        )

    text = response.text
    return text, model
