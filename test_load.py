import json
from pprint import pprint

filepath = "source_ips.json"

# Test loading the source ips
def test_load():
    with open(filepath) as data_file:
        sources = json.load(data_file)
        pprint(sources)


test_load()
