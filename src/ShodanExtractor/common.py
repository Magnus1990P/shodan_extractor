import logging
import json
import gzip
from os.path import exists
from typing import List, Dict
from time import sleep

logger = logging.getLogger()


def extract_common_keys(json_objects : List = []) -> List[str]:
    common_keys = list(json_objects[0].keys())
    for obj in json_objects[1:]:
        remove_list = [key for key in common_keys if key not in obj.keys()]
        for key in remove_list:
            common_keys.pop(common_keys.index(key))
    return common_keys


def load_shodan_files(filenamse:List[str] = []):
    hash_list = []
    lines = []
    for filename in filenamse:
        if not exists(filename):
            raise FileNotFoundError
        
        if filename.endswith(".json.gz"):
            with gzip.open(filename, "rb") as archive:
                logging.info(archive.filename)
                lines.extend(archive.readlines())
                    
        else:
            with open(filename, "rb") as raw_file:
                logging.info(filename)
                lines.extend(raw_file.readlines())
        
    data = []
    for line in lines:
        line = line.strip()
        try:
            json_obj = json.loads(line)
            data.append(json_obj)
        except:
            logging.warning(f"Error in line of data: {line}")
            continue
    return data


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


def load_config(default_config: str = "config.json", override_config: str = ""):
    config_builder = {}
    if exists(default_config):
        with open(default_config, "r", encoding="utf-8") as config_file:
            config_builder = json.load(config_file)
    else:
        raise ValueError("config file not found")

    if not override_config:
        logger.info("No override file provided, testing default convention")
        override_config = f"{default_config}.override"

    if exists(override_config):
        with open(override_config, "r", encoding="utf-8") as config_file:
            try:
                configData = json.load(config_file)
                config_builder = merge_config(current_config=config_builder, custom_config=configData)
            except Exception as e:
                logger.error(f"Error adding override config\n{e}")

    return config_builder


def get_request(url: str = "localhost", params: Dict = {}, headers: Dict = {}, timeout: int = 3, max_retries: int = 3):
    for attempt in range(0, max_retries):
        try:
            resp = get(url=url, params=params, headers=headers, timeout=timeout)
            logger.info(resp.url)
            return resp
        except reqErr.Timeout or reqErr.ReadTimeout or reqErr.ConnectTimeout or TimeoutError:
            logging.error(f"Timeout error - {attempt+1}/{max_retries} timed out")
        except reqErr.MissingSchema:
            logging.error("Missing URL schema returning")
            break
        except Exception as e:
            logging.error(f"Unknown error - {attempt+1}/{max_retries}\n{e}")
            break
        finally:
            if (attempt+1) < max_retries:
                sleep(1)
    return {}


if __name__ == "__main__":
    configFileName = "../../config/config.default.json"
    loaded_config = load_config(default_config=configFileName)
    logConfig = loaded_config["logging"]
    logging.basicConfig(
        level=logConfig["log_level"],
        format=logConfig["log_fstr_std"],
        datefmt=logConfig["log_date_formt"]
    )
    pass
