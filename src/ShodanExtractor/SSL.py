import logging
from typing import List, Dict, Optional
from json import JSONEncoder
from pydantic import BaseModel, validator


from OpenSSL import crypto

wwlogger = logging.getLogger()


class SSLEncoder(JSONEncoder):
    def default(self, obj):
        return obj.__dict__


class SSLObject(BaseModel):
    fingerprint: Optional[str] = None
    common_name: str = None
    organization: str = None
    email: str = None
    idMunicipality: Optional[int] = None
    isMember: Optional[bool] = False
    noticeHCERT: Optional[bool] = False
    noticeKCERT: Optional[bool] = False
    noticeNCSC: Optional[bool] = False
    lastReview: Optional[int] = None
    created: Optional[int] = None
    modified: Optional[int] = None
    children: Optional[List] = []

    @validator("common_name")
    def common_name_validation(cls, v):    
        return v

def certificate_extractor( raw_cert: str,bytes = None ):
    if not raw_cert:
        raise ValueError
    
    

if __name__ == "__main__":
    pass