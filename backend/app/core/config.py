from pydantic import BaseModel, Field

class Settings(BaseModel):
    APP_NAME: str = "AI-Assisted Context-Aware Cybersecurity Remediation Prioritization"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = False
    DATABASE_URL: str = Field(default="sqlite:///./cybersecurity.db")
    API_V1_STR: str = "/api"
    SECRET_KEY: str = Field(default="your-secret-key-here-change-in-production")
    MAX_GRAPH_NODES: int = 10000
    MAX_GRAPH_EDGES: int = 50000
    
    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()