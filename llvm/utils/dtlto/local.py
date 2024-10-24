import subprocess
import sys
import os
import argparse
import json
from pathlib import Path
import shutil
try:
    import jsonschema
except ImportError:
    print("Warning: jsonschema module could not be imported. Input will not be validated.")
    pass

tempFiles = []

def validate_input_json(inputJson):
    p = Path(__file__).with_name("dtlto_schema.json")

    # Load the JSON Schema from the file
    with p.open("r") as schema_file:
        schema = json.load(schema_file)

    # Validate the JSON data against the schema
    jsonschema.validate(instance=inputJson, schema=schema)

def execute(cmds):

    command = " ".join(cmds)
    print(f"{command=}")

    try:
        # Execute the command
        result = subprocess.run(cmds, capture_output=True, text=True)

        # Check if the execution was successful
        if result.returncode != 0:
            print("Execution failed:")
            print(f"{result.stdout=}")
            print(f"{result.stderr=}")

    except FileNotFoundError:
        print("Error: dbsbuild not found.")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    jsonArg = sys.argv[-1]
    extraArgs = sys.argv[1:-1]

    print(f"args = {jsonArg} {extraArgs}")

    # Load the JSON data from the input file.
    with open(jsonArg, "r") as file:
        data = json.load(file)

<<<<<<< HEAD
    # with open("orig_pretty.json", "w") as dbsJsonFile:
    #    dbsJsonFile.write(json.dumps(data, indent=4))

    if "jsonschema" in sys.modules:
        validate_input_json(data)
=======
    validate_input_json(data)
>>>>>>> 881a669ddf12 (Addressed TODOs and simplified.)

    # Iterate over the jobs and execute clang.
    jobIndex = 0
    for job in data["jobs"]:
        jobIndex += 1

        # First resolve the module references
        # and simultaneously populate the module
        # mapping.
        moduleMapNeeded = False
        moduleIdMap = []
        jobInputs = []
        for i in job["inputs"]:
            if isinstance(i, int):
                m = data["common"]["modules"][i]
                if isinstance(m, list):
                    moduleMapNeeded = True
                    moduleIdMap.append((m[0], m[1]))
                    jobInputs.append(m[1])
                else:
                    moduleIdMap.append((m, m))
                    jobInputs.append(m)
            else:
                jobInputs.append(i)
        job["inputs"] = jobInputs

        command = []
        command.append(data["common"]["codegen-tool"])

        for a in data["common"]["args"]:
            if isinstance(a, list):
                # these are references into the
                # job properties which may have
                # a prefix to handle <option>=
                # arguments.
                command.append(a[0] + job[a[1]][a[2]])
            else:
                command.append(a)

        mappingFileList = []
        if moduleMapNeeded and len(moduleIdMap) != 0:
            mappingFileName = jsonArg + "." + str(jobIndex) + ".mapping.txt"
            with open(mappingFileName, "w") as mappingFile:
                for m in moduleIdMap:
                    mappingFile.write(f"{m[0]}\t{m[1]}\n")
            command.append(f"-fthinlto-module-id-map={mappingFileName}")
            mappingFileList.append(mappingFileName)
            tempFiles.append(mappingFileName)


        execute(command)

    # Remove all temporary files.
    for f in tempFiles:
        Path(f).unlink(missing_ok=True)
