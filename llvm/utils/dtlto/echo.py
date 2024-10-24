import sys
import json
from pathlib import Path
import shutil
try:
    import jsonschema
except ImportError:
    print("Warning: jsonschema module could not be imported. Input will not be validated.")
    pass

def validate_input_json(inputJson):
    p = Path(__file__).with_name("dtlto_schema.json")

    # Load the JSON Schema from the file
    with p.open("r") as schema_file:
        schema = json.load(schema_file)

    # Validate the JSON data against the schema
    jsonschema.validate(instance=inputJson, schema=schema)

if __name__ == "__main__":
    jsonArg = sys.argv[-1]
    distributorArgs = sys.argv[1:-1]

    print(f"{distributorArgs=}")

    # Load the JSON data from the input file.
    with open(jsonArg, "r") as file:
        data = json.load(file)

    if "jsonschema" in sys.modules:
        validate_input_json(data)

    ## echo the json back to stdout
    print(json.dumps(data, indent=4))
