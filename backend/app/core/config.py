from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    APP_NAME: str = "AI-Assisted Context-Aware Cybersecurity Remediation Prioritization"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = False
    DATABASE_URL: str = Field(default="sqlite:///./cybersecurity.db")
    API_V1_STR: str = "/api"
    SECRET_KEY: str = Field(default="your-secret-key-here-change-in-production")
    MAX_GRAPH_NODES: int = 10000
    MAX_GRAPH_EDGES: int = 50000
    AI_PROVIDER: str = Field(default="groq")
    AI_MODEL: str = Field(default="openai/gpt-oss-120b")
    GROQ_API_KEY: str = Field(default="")
    OPENAI_API_KEY: str = Field(default="")
    GEMINI_API_KEY: str = Field(default="")
    AI_TIMEOUT_SECONDS: float = Field(default=30.0)
    AI_MAX_RETRIES: int = Field(default=1)
    AI_BASE_URL: str = Field(default="")
    
    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()