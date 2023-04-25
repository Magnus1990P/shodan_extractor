import logging
from typing import List, Dict, Optional
from json import JSONEncoder
from pydantic import BaseModel, validator

from ShodanExtractor.SSL import SSLObject

logger = logging.getLogger()

class ShodanObject(object):
    domain_list: List[str] = []
    hostname_list: List[str] = []
    cloud_provider: str = None
    SSL:SSLObject = None
    
    def __init__(self, data:Dict={}, config:Dict={}):
        for key,value in data.items():
            if key in config["ShodanExtractor"]["skip_keys"]:
                continue

            if key in config["ShodanExtractor"]["keys_str"]:
                self.__setattr__(key, value if value else None)
            
            elif key in config["ShodanExtractor"]["keys_int"]:
                self.__setattr__(key, int(value) if value else None)
            
            elif key == "location":
                for subkey in ["country_name", "country_code", "city"]:
                    self.__setattr__(subkey, value[subkey] if value[subkey] else None )
            
            elif key == "domains":
                if value:
                    self.domain_list.extend(value)

            elif key == "cloud":
                if "service" in value and value["service"]:
                    self.cloud_provider = value["service"]
                elif "provider" in value and value["provider"]:
                    self.cloud_provider = value["provider"]
                continue

            elif key == "hostnames":
                if value:
                    self.hostname_list.extend(value)

            elif key == "vulns":
                if value:
                    self.__setattr__("vulnerabilities", list(value.keys()) if value else None )
                    logger.info(f"vulnerabilities - {self.vulnerabilities}")
            
            elif key == "ssl":
                continue

            elif key == "http":
                continue
            
            elif key == "data":
                continue
            
            elif key == "opts":
                logger.info(f"{key} - {value.keys()}")
                continue
            else:
                logger.warn(f"{key} - {value}")
                #self.__setattr__(key,value)
        print()
        

if __name__ == "__main__":
    pass