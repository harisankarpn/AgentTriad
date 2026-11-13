"""
Model-Agnostic LLM Router (`poc/providers/model_router.py`).

Enables `lead_orchestrator.py`, `agents/database_agent/agent.py`, and
`agents/infra_agent/agent.py` to select Gemini (Vertex AI / Google AI Studio),
AWS Bedrock (Claude/Llama), Azure OpenAI, OpenAI, or any LiteLLM-compatible proxy
strictly via environment variables while keeping Vertex AI Gemini (`gemini-2.5-flash`)
as the 100% backward-compatible default.

Environment Variables:
  - `AAAS_LLM_PROVIDER`: `vertex` (default) | `gemini` | `litellm` | `bedrock` | `azure_openai` | `openai`
  - `AAAS_LLM_MODEL`: Override model name (falls back to `AAAS_GEMINI_MODEL` / `ADK_MODEL` / `gemini-2.5-flash`)
  - `AAAS_LLM_API_BASE`: Custom OpenAI/LiteLLM proxy base URL (e.g. `http://localhost:4000/v1`)
  - `AAAS_LLM_API_KEY`: API key for OpenAI / LiteLLM proxy
  - `AZURE_OPENAI_ENDPOINT` / `AZURE_OPENAI_API_KEY` / `AZURE_OPENAI_API_VERSION` / `AZURE_OPENAI_DEPLOYMENT`
  - `AWS_BEDROCK_REGION` / `AWS_REGION`
"""

from __future__ import annotations

import json
import os
from typing import Any, AsyncGenerator, Dict, List, Optional

import httpx

DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"


def get_llm_provider_config(default_model: str = DEFAULT_GEMINI_MODEL) -> Dict[str, Any]:
    """Reads effective model-agnostic LLM routing settings from environment variables."""
    provider = (os.getenv("AAAS_LLM_PROVIDER") or "vertex").strip().lower()
    raw_model = (
        os.getenv("AAAS_LLM_MODEL")
        or os.getenv("ADK_MODEL")
        or os.getenv("AAAS_GEMINI_MODEL")
        or default_model
    ).strip()

    if provider == "bedrock" and not raw_model.startswith("bedrock/"):
        litellm_model = f"bedrock/{raw_model}"
    elif provider == "azure_openai" and not raw_model.startswith("azure/"):
        deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT") or raw_model
        litellm_model = f"azure/{deployment}"
    elif provider == "openai" and "/" not in raw_model:
        litellm_model = f"openai/{raw_model}"
    else:
        litellm_model = raw_model

    return {
        "provider": provider,
        "model": raw_model,
        "litellm_model": litellm_model,
        "api_base": (
            os.getenv("AAAS_LLM_API_BASE")
            or os.getenv("AZURE_OPENAI_ENDPOINT")
            or ""
        ).rstrip("/"),
        "api_key": (
            os.getenv("AAAS_LLM_API_KEY")
            or os.getenv("AZURE_OPENAI_API_KEY")
            or os.getenv("OPENAI_API_KEY")
            or ""
        ).strip(),
        "azure_api_version": os.getenv("AZURE_OPENAI_API_VERSION", "2024-06-01").strip(),
        "aws_region": os.getenv("AWS_BEDROCK_REGION") or os.getenv("AWS_REGION") or "us-east-1",
    }


def _build_custom_adk_base_llm(cfg: Dict[str, Any]) -> Any:
    """
    Lightweight `google.adk.models.BaseLlm` fallback when `AAAS_LLM_PROVIDER` targets
    Bedrock / Azure OpenAI / OpenAI / LiteLLM Proxy and the optional `litellm` Python
    package is not installed in the environment.
    """
    from google.adk.models.base_llm import BaseLlm
    from google.adk.models.llm_response import LlmResponse
    from google.genai import types

    router_client = ModelAgnosticLLMClient(config=cfg)

    class _RoutedAdkLlm(BaseLlm):
        model: str = cfg["litellm_model"]

        @classmethod
        def supported_models(cls) -> List[str]:
            return [r".*"]

        async def generate_content_async(
            self, llm_request: Any, stream: bool = False
        ) -> AsyncGenerator[LlmResponse, None]:
            prompt_parts: List[str] = []
            sys_inst = getattr(getattr(llm_request, "config", None), "system_instruction", None)
            if sys_inst:
                prompt_parts.append(f"[SYSTEM]\n{sys_inst}")
            for content in getattr(llm_request, "contents", []) or []:
                role = getattr(content, "role", "user")
                texts = [getattr(p, "text", "") for p in (getattr(content, "parts", None) or []) if getattr(p, "text", None)]
                if texts:
                    prompt_parts.append(f"[{role.upper()}]\n" + "\n".join(texts))
            combined = "\n\n".join(prompt_parts)
            text = router_client.generate_text(combined)
            yield LlmResponse(
                content=types.Content(
                    role="model",
                    parts=[types.Part.from_text(text=text or "")],
                )
            )

    return _RoutedAdkLlm(model=cfg["litellm_model"])


def resolve_adk_model(
    default_model: str = DEFAULT_GEMINI_MODEL,
    provider_override: Optional[str] = None,
    model_override: Optional[str] = None,
) -> Any:
    """
    Resolves the `model` argument passed to `google.adk.agents.Agent(model=...)`:
      - `vertex` / `gemini` (default): returns plain Gemini model string (e.g. `gemini-2.5-flash`),
        preserving 100% native Vertex AI / Google ADK Gemini tool-calling behavior.
      - `litellm` / `bedrock` / `azure_openai` / `openai`: uses `google.adk.models.lite_llm.LiteLlm`
        when `litellm` is installed, or falls back cleanly to `_RoutedAdkLlm(BaseLlm)`.
    """
    cfg = get_llm_provider_config(default_model=default_model)
    if provider_override:
        cfg["provider"] = provider_override.strip().lower()
    if model_override:
        cfg["model"] = model_override.strip()
        if cfg["provider"] == "bedrock" and not cfg["model"].startswith("bedrock/"):
            cfg["litellm_model"] = f"bedrock/{cfg['model']}"
        elif cfg["provider"] == "azure_openai" and not cfg["model"].startswith("azure/"):
            cfg["litellm_model"] = f"azure/{cfg['model']}"
        else:
            cfg["litellm_model"] = cfg["model"]

    if cfg["provider"] in ("vertex", "gemini"):
        return cfg["model"]

    try:
        from google.adk.models.lite_llm import LiteLlm  # type: ignore

        extra: Dict[str, Any] = {}
        if cfg["api_base"]:
            extra["api_base"] = cfg["api_base"]
        if cfg["api_key"]:
            extra["api_key"] = cfg["api_key"]
        return LiteLlm(model=cfg["litellm_model"], **extra)
    except ImportError:
        return _build_custom_adk_base_llm(cfg)


class ModelAgnosticLLMClient:
    """
    Unified synchronous text/JSON completion client used by Atlas (`lead_orchestrator.py`)
    and optional fallback paths across Vertex AI Gemini, LiteLLM, AWS Bedrock Converse,
    Azure OpenAI, and OpenAI-compatible HTTP endpoints.
    """

    def __init__(
        self,
        genai_client: Optional[Any] = None,
        default_model: str = DEFAULT_GEMINI_MODEL,
        config: Optional[Dict[str, Any]] = None,
        http_client: Optional[Any] = None,
    ) -> None:
        self._genai_client = genai_client
        self.config = config or get_llm_provider_config(default_model=default_model)
        self._http_client = http_client

    @property
    def provider(self) -> str:
        return str(self.config.get("provider", "vertex"))

    @property
    def model_name(self) -> str:
        return str(self.config.get("model", DEFAULT_GEMINI_MODEL))

    @property
    def is_available(self) -> bool:
        if self.provider in ("vertex", "gemini"):
            return self._genai_client is not None
        return True

    def generate_text(
        self,
        prompt: str,
        *,
        response_mime_type: Optional[str] = None,
        temperature: float = 0.2,
    ) -> Optional[str]:
        provider = self.provider

        # 1. Native Vertex AI / Gemini SDK (default)
        if provider in ("vertex", "gemini"):
            if self._genai_client is None:
                return None
            try:
                from google.genai import types as genai_types

                gen_cfg = (
                    genai_types.GenerateContentConfig(
                        response_mime_type=response_mime_type,
                        temperature=temperature,
                    )
                    if response_mime_type
                    else None
                )
                kwargs: Dict[str, Any] = {"model": self.model_name, "contents": prompt}
                if gen_cfg is not None:
                    kwargs["config"] = gen_cfg
                resp = self._genai_client.models.generate_content(**kwargs)
                return resp.text.strip() if (resp and getattr(resp, "text", None)) else None
            except Exception:
                return None

        # 2. LiteLLM Python SDK (supports bedrock/, azure/, openai/, anthropic/, vertex_ai/)
        try:
            import litellm  # type: ignore

            call_kwargs: Dict[str, Any] = {
                "model": self.config["litellm_model"],
                "messages": [{"role": "user", "content": prompt}],
                "temperature": temperature,
            }
            if self.config.get("api_base"):
                call_kwargs["api_base"] = self.config["api_base"]
            if self.config.get("api_key"):
                call_kwargs["api_key"] = self.config["api_key"]
            if response_mime_type == "application/json":
                call_kwargs["response_format"] = {"type": "json_object"}
            resp = litellm.completion(**call_kwargs)
            return resp["choices"][0]["message"]["content"].strip()
        except ImportError:
            pass
        except Exception:
            return None

        # 3. Direct AWS Bedrock Converse API (lazy boto3)
        if provider == "bedrock":
            try:
                import boto3  # type: ignore

                br = boto3.client("bedrock-runtime", region_name=self.config["aws_region"])
                model_id = self.model_name.removeprefix("bedrock/")
                resp = br.converse(
                    modelId=model_id,
                    messages=[{"role": "user", "content": [{"text": prompt}]}],
                    inferenceConfig={"temperature": temperature},
                )
                parts = resp.get("output", {}).get("message", {}).get("content") or []
                texts = [p.get("text", "") for p in parts if p.get("text")]
                return "".join(texts).strip() or None
            except Exception:
                return None

        # 4. Direct Azure OpenAI REST API
        if provider == "azure_openai":
            endpoint = self.config.get("api_base", "")
            api_key = self.config.get("api_key", "")
            deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT") or self.model_name.removeprefix("azure/")
            api_ver = self.config.get("azure_api_version", "2024-06-01")
            if not endpoint or not api_key:
                return None
            url = f"{endpoint}/openai/deployments/{deployment}/chat/completions?api-version={api_ver}"
            payload: Dict[str, Any] = {
                "messages": [{"role": "user", "content": prompt}],
                "temperature": temperature,
            }
            if response_mime_type == "application/json":
                payload["response_format"] = {"type": "json_object"}
            return self._post_chat_completions(url, payload, {"api-key": api_key, "Content-Type": "application/json"})

        # 5. OpenAI or LiteLLM HTTP Proxy (`/v1/chat/completions`)
        api_base = self.config.get("api_base") or "https://api.openai.com/v1"
        api_key = self.config.get("api_key", "")
        url = f"{api_base}/chat/completions" if api_base.endswith("/v1") else f"{api_base}/v1/chat/completions"
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        payload = {
            "model": self.model_name.removeprefix("openai/"),
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
        }
        if response_mime_type == "application/json":
            payload["response_format"] = {"type": "json_object"}
        return self._post_chat_completions(url, payload, headers)

    def _post_chat_completions(
        self,
        url: str,
        payload: Dict[str, Any],
        headers: Dict[str, str],
    ) -> Optional[str]:
        try:
            if self._http_client is not None:
                resp = self._http_client.post(url, json=payload, headers=headers)
            else:
                with httpx.Client(timeout=30.0) as client:
                    resp = client.post(url, json=payload, headers=headers)
            if resp.status_code != 200:
                return None
            data = resp.json()
            choices = data.get("choices") or []
            if not choices:
                return None
            return str((choices[0].get("message") or {}).get("content") or "").strip() or None
        except Exception:
            return None

    def describe(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "model": self.model_name,
            "litellm_model": self.config.get("litellm_model"),
            "api_base_configured": bool(self.config.get("api_base")),
        }
