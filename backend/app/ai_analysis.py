import os
from google import genai
from google.genai import types

_client = None
# Starting point only - Google has been retiring Gemini Flash model
# ids every few months (gemini-flash-latest -> pointed at discontinued
# gemini-2.0-flash; gemini-2.5-flash -> retired "for new users" in
# favor of gemini-3.8-flash, as of Oct 2026). Pinning any single id
# here just means this breaks again next time Google rolls a model.
# So generate_threat_analysis() below auto-recovers from a 404 by
# asking the API what's actually live right now and retrying once -
# this env var is only the first guess, not a hard requirement.
DEFAULT_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")

# Cache of the model id that last actually worked, so once we discover
# a live one we don't re-discover on every single request.
_working_model = None

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


def _discover_live_flash_model(client) -> str:
    """
    Asks the Gemini API itself which models are currently callable and
    picks a Flash-tier one (cheap/fast - good enough for a short SOC
    report, and what the free AI Studio tier is meant for). This is
    the fallback for when a hardcoded model id gets retired out from
    under us, which has now happened twice in the same week.
    """
    candidates_found = []
    for m in client.models.list():
        name = getattr(m, "name", "") or ""
        short_name = name.split("/", 1)[-1]  # "models/gemini-3.8-flash" -> "gemini-3.8-flash"
        actions = getattr(m, "supported_actions", None) or []
        if "generateContent" in actions and "flash" in short_name.lower():
            candidates_found.append(short_name)

    if not candidates_found:
        raise RuntimeError(
            "Gemini API returned no usable Flash-tier model for this API key. "
            "Check aistudio.google.com/models for what's currently available "
            "and set GEMINI_MODEL explicitly."
        )
    # Prefer the lexicographically highest version string (newest), e.g.
    # gemini-3.8-flash over gemini-2.5-flash.
    candidates_found.sort(reverse=True)
    return candidates_found[0]


def generate_threat_analysis(flow: dict):
    """Returns (analysis_markdown, model_used)."""
    global _working_model
    client = get_gemini_client()
    model = _working_model or DEFAULT_MODEL
    prompt = build_prompt(flow)

    def _call(model_id):
        return client.models.generate_content(
            model=model_id,
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_INSTRUCTION,
                max_output_tokens=900,
            ),
        )

    try:
        response = _call(model)
    except Exception as e:
        is_not_found = "404" in str(e) or "NOT_FOUND" in str(e)
        if not is_not_found:
            raise RuntimeError(f"Gemini request failed ({model}): {e}") from e
        # The configured/cached model id was retired - ask the API what's
        # live right now and retry once with that instead of failing.
        try:
            fallback_model = _discover_live_flash_model(client)
            response = _call(fallback_model)
            model = fallback_model
            _working_model = fallback_model  # remember it for next time
        except Exception as e2:
            raise RuntimeError(
                f"Gemini request failed: configured model '{model}' is no longer "
                f"available ({e}), and auto-discovering a replacement also failed "
                f"({e2}). Set GEMINI_MODEL to a current id from aistudio.google.com/models."
            ) from e2

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
