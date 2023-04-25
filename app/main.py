#!/usr/bin/env python3
# coding: utf-8

import logging
from typing import List, Dict, Optional
import json
import click
from os.path import exists

from pydantic import BaseModel, ValidationError

from ShodanExtractor.common import load_config, load_shodan_files, extract_common_keys
from ShodanExtractor import ShodanObject

from zipfile import ZipFile
import gzip





@click.command("main")
@click.option("--shodan-file", "-f", multiple=True, help="Pass a key to specify that key from the results")
@click.option("--enable-c99", is_flag=True, show_default=True, default=False, help="Enable c99nl scan for expanding on metadata information")
@click.option("--enable-whois", is_flag=True, show_default=True, default=False, help="Enable WHOIS lookup for expanding on metadata information")
@click.option("--enable-vt", is_flag=True, show_default=True, default=False, help="Enable VirusTotal lookup for expanding on metadata information")
@click.pass_context
def main(ctx, enable_c99, enable_vt, enable_whois, shodan_file):
    config = load_config(default_config="../config/config.default.json",
                         override_config="../config/config.override.json")
    logConfig = config["logging"]
    logging.basicConfig(
        level=logConfig["log_level"],
        format=logConfig["log_fstr_std"],
        datefmt=logConfig["log_date_formt"]
    )

    json_objects = load_shodan_files(filenamse=shodan_file)
    
    shodan_hashes = []
    shodan_objects = []
    while json_objects:
        obj = json_objects.pop()
        if obj["hash"] in shodan_hashes:
            logging.warning(f"Skipped existing shodan object based on hash")
            continue
        shodan_object = ShodanObject.ShodanObject(data=obj, config=config)
        shodan_objects.append(shodan_object)


if __name__ == "__main__":
    main()