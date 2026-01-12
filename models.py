from enum import Enum
from typing import Any, Dict, List, Union, Optional
from pydantic import BaseModel, Field


class ResponseModel(BaseModel):
    code: int = 0
    message: str = ''
    data: Any


class HttpRequestModel(BaseModel):
    """HTTP request model for generic HTTP request API"""
    method: str = Field(..., description='HTTP method, such as GET, POST, PUT, DELETE, etc.', examples=['GET', 'POST'])
    url: str = Field(..., description='Target URL address', examples=['http://example.com/api'])
    headers: Optional[Dict[str, str]] = Field(None, description='Request headers, key-value dictionary', examples=[{'Content-Type': 'application/json'}])
    payload: Optional[Union[str, Dict, List]] = Field(None, description='Request body, can be string, dict or list', examples=['{"key": "value"}'])
