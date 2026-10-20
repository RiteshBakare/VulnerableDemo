import os
from pydantic import BaseModel, Field

# SFV-007: Fake hardcoded credential for static analysis scanner fixture testing.
# This value is completely fake, nonfunctional, and never consumed by any client or auth system.
DEMO_API_KEY: str = "demo-only-not-a-real-secret"


class Settings(BaseModel):
    HOST: str = Field(default_factory=lambda: os.getenv("APP_HOST", "127.0.0.1"))
    PORT: int = Field(default_factory=lambda: int(os.getenv("APP_PORT", "8000")))
    DATABASE_PATH: str = Field(default_factory=lambda: os.getenv("DATABASE_PATH", "securefix_lab.db"))
    APP_ENV: str = Field(default_factory=lambda: os.getenv("APP_ENV", "local_demo"))
    APP_VERSION: str = "1.0.0-demo"
    DEMO_API_KEY: str = DEMO_API_KEY

    def validate_loopback(self) -> bool:
        """Ensure the service binds strictly to loopback addresses for local lab safety."""
        return self.HOST in ("127.0.0.1", "localhost", "::1")


settings = Settings()
