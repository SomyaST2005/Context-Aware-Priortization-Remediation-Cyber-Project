"""
Base Pydantic schemas with common configurations.
"""
from pydantic import BaseModel as PydanticBaseModel
from typing import Generic, TypeVar

T = TypeVar('T')


class BaseSchema(PydanticBaseModel):
    """Base schema with common configuration."""
    class Config:
        from_attributes = True
        validate_assignment = True


class PaginatedResponse(BaseSchema, Generic[T]):
    """Paginated response wrapper."""
    items: list[T]
    total: int
    page: int
    size: int
    pages: int