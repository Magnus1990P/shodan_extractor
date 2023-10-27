Shodan Extractor
================
Extracts and parses data into a better format for large scale analysis of large host set.

It expands the JSON files into a Excel spreadsheet format for a more visual sorting and analysis of the datasets.




## Setup
- Install the Shodan_Extractor as a package using pip `python -m pip install -e . --user`
- Install dependencies if needed (the list resides in the setup as well) - `python -m pip install -r requirements.txt --user`
- Set up the override configuration file, which contains API-keys

## Override configuration
- Copy the `config.default.json` file to `config.override.json` and remove the keys you don't want to change
- Add the API-keys for the defined services you want to use
- Include the options for the service when running the extractor


## Run the script
The output below is the help menu.
- **-f**: string containing the path of a directory containing shodan data files or just shodan files
    - NB! Can be specified multiple times 
    - Files can be both `json` text files and compressed data files
- **-o**: Output directory to store the data
- **--enable-c99**: Enable c99 lookup for extending the dataset
- **--enable-whois**: Enable whois lookup for extending the dataset
    - NB! not implemented
- **--enable-vt**: Enable VirusTotal lookup for extending the dataset
    - NB! not implemented

```
# python.exe main.py --help
Usage: main.py [OPTIONS]

Options:
  -f, --files PATH       Shodan JSON file, compressed or uncompressed
  -o, --output-dir PATH
  --enable-c99           Enable c99nl scan for expanding on metadata
                         information
  --enable-whois         Enable WHOIS lookup for expanding on metadata
                         information
  --enable-vt            Enable VirusTotal lookup for expanding on metadata
                         information
  --help                 Show this message and exit.
  ```