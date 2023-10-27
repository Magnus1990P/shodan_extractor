import logging
import json
import gzip
import ipaddress
import datetime
from c99api import EndpointClient
from typing import List, Dict, Optional
from os.path import exists


logger = logging.getLogger()


def enrich_object_c99(object, c99_key:str=""):
    c99 = EndpointClient
    c99.key = c99_key
    ip = object["IPAddress"]
    resp = c99.gethostname(ip)
    if resp["success"] and ip != resp["hostname"] and resp["hostname"] not in object["hostname_list"]:
        logging.info(f"gethostname: {resp['hostname']}")
        object["hostname_list"].append(resp["hostname"])
    resp = c99.ip2domains(ip)
    if resp["success"] and resp["count"] >= 1:
        logging.info(f"ip2domains: {resp['data']}")
        object["domain_list"].extend([hname for hname in resp["data"] if hname not in object["domain_list"]])


def merge_config(current_config: Dict[int, str] = {}, custom_config: Dict[int, str] = {}):
    for key, value in custom_config.items():
        if key in current_config.keys():
            if isinstance(value, (list,)):
                current_config[key] = list(set(current_config[key].extend(current_config[key])))
            elif isinstance(value, (dict,)):
                current_config[key] = merge_config(current_config[key], custom_config[key])
            else:
                current_config[key] = value
        else:
            current_config.update({key: value})
    return current_config


def load_config(default_config: str = "config.default.json", override_config: str = ""):
    config_builder = {}
    if exists(default_config):
        with open(default_config, "r", encoding="utf-8") as config_file:
            config_builder = json.load(config_file)
    else:
        raise ValueError("config file not found")
    if exists(override_config):
        with open(override_config, "r", encoding="utf-8") as config_file:
            try:
                configData = json.load(config_file)
                config_builder = merge_config(current_config=config_builder, custom_config=configData)
            except Exception as e:
                logger.error(f"Error adding override config\n{e}")
    return config_builder


def decode_shodan(obj:dict={}):
    try:
        parsed_object = {
            "domain_list": obj["domains"] if "domains" in obj else [],
            "hostname_list": [obj["_shodan"]["options"]["hostname"]] if "hostname" in obj["_shodan"]["options"] else [],
            "product": obj["product"] if "product" in obj else "",
            "version": obj["version"] if "version" in obj else "",
            "operating_system": obj["os"],
            "IPAddress": ipaddress.ip_address(obj["ip_str"]),
            "scanned": datetime.datetime.fromisoformat(obj["timestamp"]),
            "protocol": obj["transport"] if "transport" in obj else "",
            "port": obj["port"],
            "internet_service_provider": obj["isp"],
            "organisation": obj["org"],
            "country": obj["location"]["country_name"] if "country_name" in obj["location"] else "",
            "city": obj["location"]["city"] if "city" in obj["location"] else ""
        }
        parsed_object["hostname_list"].extend([hname.strip() for hname in obj["hostnames"]])
        parsed_object["hostname_list"] = ", ".join(list(set(parsed_object["hostname_list"]))) if parsed_object["hostname_list"] else None
        parsed_object["domain_list"] = ", ".join(list(set(parsed_object["domain_list"]))) if parsed_object["domain_list"] else None
        
    except Exception as e:
        logging.error(e)
        return {}
    try:
        if "ssl" in obj and "cert" in obj["ssl"]:
            cert = obj["ssl"]
            if "subject" in cert["cert"]:
                if "CN" in cert["cert"]["subject"]:
                    parsed_object["ssl_SAN"] = [cert["cert"]["subject"]["CN"]]
                elif "unstructuredName" in cert["cert"]["subject"]:
                    parsed_object["ssl_SAN"] = [cert["cert"]["subject"]["unstructuredName"]]
                else:
                    parsed_object["ssl_SAN"] = []
            for alt in cert["cert"]["extensions"]:
                if alt["name"]=="subjectAltName" and alt["data"]:
                    i = 0
                    while i < len(alt["data"]):
                        if alt["data"][i] == "\\":
                            i += 4
                            continue
                        next_slash = alt["data"][i:].find("\\")
                        if next_slash >= 0:
                            parsed_object["ssl_SAN"].append(alt["data"][i:i+next_slash])
                            i += next_slash
                        else:
                            parsed_object["ssl_SAN"].append(alt["data"][i:])
                            i = len(alt["data"])
                        if parsed_object["ssl_SAN"][-1] == "0.":
                            parsed_object["ssl_SAN"].pop()
            parsed_object["ssl_SAN"] = ", ".join(list(set(parsed_object["ssl_SAN"]))) if parsed_object["ssl_SAN"] else None
            if "issuer" in cert["cert"]:
                if "O" in cert["cert"]["issuer"]:
                    parsed_object["ssl_issuer"] = cert["cert"]["issuer"]["O"]
                elif "CN" in cert["cert"]["issuer"]:
                    parsed_object["ssl_issuer"] = cert["cert"]["issuer"]["CN"]
                elif "unstructuredName" in cert["cert"]["issuer"]:
                    parsed_object["ssl_issuer"] = cert["cert"]["issuer"]["unstructuredName"]
                else:
                    print("ISSUER:",cert["cert"]["issuer"])
            parsed_object["ssl_fingerprint"] = cert["cert"]["fingerprint"]["sha256"]
            parsed_object["ssl_serial"] = cert["cert"]["serial"]
            parsed_object["ssl_ja3"] = cert["ja3s"]
            parsed_object["ssl_jarm"] = cert["jarm"]
    except Exception as e:
        logging.error(e)
    return parsed_object


def dict_explode(d, rem_keys, row):
    if rem_keys==[]:
        temp = row.copy()
        return [temp]
    key = rem_keys[0]
    rows = []

    if isinstance(d[key], (list,)):
        if d[key] == None or len(d[key]) == 0:
            row[key] = d[key]
            rows.extend(dict_explode(d, rem_keys[1:], row))
        else:
            for val in d[key]:
                row[key] = val
                rows.extend(dict_explode(d, rem_keys[1:], row))
    else:
        row[key] = d[key]
        rows.extend(dict_explode(d, rem_keys[1:], row))
    return rows


def load_shodan_files(filename:str="", config:Dict={}):
    if not exists(filename):
        logging.error(f"File not found: {filename}")
        raise FileNotFoundError
    logging.info(f"Loading file: {filename}")
    if filename.endswith(".json.gz"):
        with gzip.open(filename, "rb") as archive:
            lines = archive.readlines()
    else:
        with open(filename, "rb") as raw_file:
            lines = raw_file.readlines()
    data = []
    error_count = 0
    for line in lines:
        try:
            json_obj = json.loads(line)
            try:
                obj = decode_shodan(obj=json_obj)
                data.append(obj)
            except Exception as e:
                logger.warning(e)
        except:
            error_count += 1
            continue
    if error_count > 0:
        logging.error(f"{filename} - Errors occurred during loading of data: {error_count}")
    return data


if __name__ == "__main__":
    configFileName = "../../config/config.default.json"
    loaded_config = load_config(default_config=configFileName)
    logConfig = loaded_config["logging"]
    logging.basicConfig(
        level=logConfig["log_level"],
        format=logConfig["log_fstr_std"],
        datefmt=logConfig["log_date_formt"]
    )
