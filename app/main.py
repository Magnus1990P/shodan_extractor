#!/usr/bin/env python3
# coding: utf-8

import logging
import click

import pandas as pd
from typing import List, Dict, Optional
from os.path import isdir, isfile
from os import walk

from ShodanExtractor.common import load_config, load_shodan_files, enrich_object_c99


@click.command("main")
@click.option("-f", "--files", multiple=True, help="Shodan JSON file, compressed or uncompressed", type=click.Path(exists=True, readable=True))
@click.option("-o", "--output-dir", multiple=False, help="", type=click.Path(exists=True, writable=True), default="./")
@click.option("--enable-c99", is_flag=True, default=False, help="Enable c99nl scan for expanding on metadata information")
@click.option("--enable-whois", is_flag=True, default=False, help="Enable WHOIS lookup for expanding on metadata information")
@click.option("--enable-vt", is_flag=True, default=False, help="Enable VirusTotal lookup for expanding on metadata information")
@click.pass_context
def main(ctx, enable_c99:bool=False, enable_whois:bool=False, enable_vt:bool=False, files:List=[], output_dir:str="./"):
    config = load_config(default_config="config.default.json", override_config="config.override.json")

    logConfig = config["logging"]
    logging.basicConfig(
        level=logConfig["log_level"],
        format=logConfig["log_fstr_std"],
        datefmt=logConfig["log_date_formt"]
    )

    logging.info(f"""MAIN
enable_c99:   {enable_c99}
enable_whois: {enable_whois}
enable_vt:    {enable_vt}
input_list:   {', '.join(files)}""")

    filepaths = []
    for filepath in files:
        if isdir(filepath):
            for root, dirlist, filelist in walk(filepath):
                filepaths.extend([f"{root}/{fname}" for fname in filelist if fname.endswith(".json.gz") or fname.endswith(".json")])
        elif filepath.endswith(".json.gz") or filepath.endswith(".json"):
            filepaths.append(filepath)
    
    shodan_data = []
    for filepath in filepaths:
        print(filepath)
        shodan_data.extend(load_shodan_files(filename=filepath, config=config))
    
    if enable_c99 and config["global"]["C99api"]:
        for shodan_object in shodan_data:
            enrich_object_c99(shodan_object, c99_key=config["global"]["C99api"])
        
    df = pd.DataFrame(shodan_data)
    logging.info(f"Elements loaded: {len(shodan_data)}")
    
    output_dir = output_dir[":-1"] if output_dir.endswith("//") else output_dir
    if isdir(output_dir):
        df.to_excel(f"{output_dir}/shodan_export.xlsx", index=False)
          

if __name__ == "__main__":
    main()