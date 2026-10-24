from typing import Literal
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, IPvAnyAddress

class AuthEvent(BaseModel):
    model_config = ConfigDict(frozen = True)
    
    timestamp: AwareDatetime
    source_ip: IPvAnyAddress
    username: str = Field(min_length = 1, max_length = 64)
    outcome: Literal["success", "failure"]
    raw: str = Field(max_length = 2048)
