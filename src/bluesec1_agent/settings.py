from pathlib import Path
from typing import Any, Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

_ENV_FILE = Path(__file__).resolve().parents[2] / ".env"


class RuntimeSettings(BaseSettings):
    """Scenario-runtime and harness settings; enough for the Claude Code MCP server."""

    model_config = SettingsConfigDict(
        env_file=_ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    scenario_runtime_endpoint: str = Field(
        default="127.0.0.1:50051",
        validation_alias="SCENARIO_RUNTIME_ENDPOINT",
        min_length=1,
    )
    scenario_runtime_token: SecretStr = Field(
        validation_alias="SCENARIO_RUNTIME_TOKEN",
        min_length=1,
    )
    scenario_runtime_verify_tls: bool = Field(
        default=True,
        validation_alias="SCENARIO_RUNTIME_VERIFY_TLS",
    )
    scenario_runtime_arena: str | None = Field(
        default=None,
        validation_alias="SCENARIO_RUNTIME_ARENA",
        min_length=1,
        max_length=64,
    )
    remote_run_label: str = Field(
        default="bluesec1-agent",
        validation_alias="REMOTE_RUN_LABEL",
        min_length=1,
    )
    agent_name: str = Field(
        default="bluesec1-agent",
        validation_alias="AGENT_NAME",
        min_length=1,
        max_length=255,
    )

    # The runtime's hidden per-task call budget grows with the task (about 8-16 calls on small
    # tasks, 19 or more on medium, 23-53 on large): past 12 reads still find key objects.
    agent_soft_call_budget: int = Field(
        default=16,
        validation_alias="BLUESEC_AGENT_SOFT_BUDGET",
        ge=1,
        le=100,
    )
    agent_hard_call_budget: int = Field(
        default=20,
        validation_alias="BLUESEC_AGENT_HARD_BUDGET",
        ge=1,
        le=100,
    )
    agent_max_parallel_calls: int = Field(
        default=4,
        validation_alias="BLUESEC_AGENT_MAX_PARALLEL_CALLS",
        ge=1,
        le=16,
    )
    agent_concurrency: int = Field(
        default=1,
        validation_alias="BLUESEC_AGENT_CONCURRENCY",
        ge=1,
        le=8,
    )
    agent_transcript_dir: str | None = Field(
        default="runs",
        validation_alias="BLUESEC_TRANSCRIPT_DIR",
    )
    agent_tool_denylist: str = Field(
        default="",
        validation_alias="BLUESEC_TOOL_DENYLIST",
    )


class JevSettings(BaseSettings):
    """TypeSafe Jev access for the offline shadow evaluation (scripts/jev_shadow.py)."""

    model_config = RuntimeSettings.model_config

    typesafe_api_key: SecretStr = Field(validation_alias="TYPESAFE_API_KEY", min_length=1)
    jev_model: str = Field(default="jev-latest", validation_alias="JEV_MODEL", min_length=1)
    jev_endpoint: str = Field(
        default="https://api.typesafe.ai/v1/systemone",
        validation_alias="JEV_ENDPOINT",
        min_length=1,
    )
    jev_timeout_seconds: float = Field(
        default=10.0,
        validation_alias="JEV_TIMEOUT_SECONDS",
        gt=0,
    )


class Settings(RuntimeSettings):
    """Runtime settings plus the OpenAI-compatible provider used by the API agents."""

    llm_base_url: str = Field(validation_alias="LLM_BASE_URL", min_length=1)
    llm_api_key: SecretStr = Field(validation_alias="LLM_API_KEY", min_length=1)
    llm_default_model: str = Field(validation_alias="LLM_DEFAULT_MODEL", min_length=1)
    llm_timeout_seconds: float = Field(
        default=120.0,
        validation_alias="LLM_TIMEOUT_SECONDS",
        gt=0,
    )
    llm_max_completion_tokens: int = Field(
        default=16_384,
        validation_alias="LLM_MAX_COMPLETION_TOKENS",
        gt=0,
    )
    llm_max_step_retries: int = Field(
        default=3,
        validation_alias="LLM_MAX_STEP_RETRIES",
        ge=1,
        le=5,
    )
    agent_max_steps: int = Field(
        default=100,
        validation_alias="BLUESEC_AGENT_MAX_STEPS",
        ge=1,
        le=100,
    )

    agent_mode: Literal["tools", "sgr"] = Field(
        default="tools",
        validation_alias="AGENT_MODE",
    )
    llm_temperature: float | None = Field(
        default=None,
        validation_alias="LLM_TEMPERATURE",
        ge=0,
        le=2,
    )
    llm_parallel_tool_calls: bool | None = Field(
        default=None,
        validation_alias="LLM_PARALLEL_TOOL_CALLS",
    )
    llm_tool_choice: Literal["required", "auto"] = Field(
        default="required",
        validation_alias="LLM_TOOL_CHOICE",
    )
    llm_extra_body: dict[str, Any] | None = Field(
        default=None,
        validation_alias="LLM_EXTRA_BODY",
    )
    agent_prompt_file: str | None = Field(
        default=None,
        validation_alias="BLUESEC_PROMPT_FILE",
    )
