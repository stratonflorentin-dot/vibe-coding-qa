# Vibe Coding QA - local secrets / overrides (TEMPLATE)
#
#   1. Copy this file to  vcqa.local.ps1   (that filename is gitignored).
#   2. Paste your real AI provider API key between the quotes below.
#   3. Run  .\run-local.ps1  - the launcher loads vcqa.local.ps1 and passes
#      these to the backend process only. The key never reaches the browser,
#      the built JS, or the SQLite database.
#
# AI is OPTIONAL. The scanner and the release gate work with no key at all.

# --- Required for AI: your provider API key (OpenRouter / OpenAI / Groq / ...) ---
# Leave empty to keep AI off. Paste your key between the quotes to turn AI on.
$env:VCQA_AI_API_KEY = ""

# --- Optional: choose the provider up front (or set these in Settings -> AI) -----
$env:VCQA_AI_PROVIDER = "openrouter"
$env:VCQA_AI_BASE_URL = "https://openrouter.ai/api/v1"
$env:VCQA_AI_MODEL    = "openai/gpt-4o-mini"

# OpenAI direct instead of OpenRouter? Use these two lines instead of the ones above:
# $env:VCQA_AI_BASE_URL = "https://api.openai.com/v1"
# $env:VCQA_AI_MODEL    = "gpt-4o-mini"
