import subprocess
import sys
import os
import argparse
import json
from pathlib import Path
import shutil
import jsonschema
from jsonschema import validate

DBSBUILD = "dbsbuild.exe"
DBSDEFAULTINSTALL = "C:\\Program Files (x86)\\SCE\\Common\\SN-DBS\\bin\\dbsbuild.exe"

tempFiles = []

def validate_input_json(inputJson):
    p = Path(__file__).with_name("dtlto_schema.json")

    # Load the JSON Schema from the file
    with p.open("r") as schema_file:
        schema = json.load(schema_file)

    # Validate the JSON data against the schema
    validate(instance=inputJson, schema=schema)


def find_DBSBuild():
    """Check whether `name` is on the PATH and marked as executable."""
    w = shutil.which(DBSBUILD)
    return w if w is not None else DBSDEFAULTINSTALL


def execute_script(json_script_path, other_args):
    # Check if the file exists
    if not os.path.isfile(json_script_path):
        print(f"Error: The file {json_script_path} does not exist.")
        sys.exit(1)

    # Prepare the command to execute dbsbuild.exe with the JSON script and other arguments
    command = [find_DBSBuild(), "-s", json_script_path] + other_args

    jc = ""
    for c in command:
        jc += " "
        jc += str(c)
    print(f"command = {jc}")

    try:
        # Execute the command
        result = subprocess.run(command, capture_output=True, text=True)

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


def dbsJobOject(command, inputs):
    explicitInputFiles = []
    for f in inputs:
        explicitInputFiles.append({"filename": f})

    return {
        "command": command,
        "explicit_input_files": explicitInputFiles,
        "timeout": 3000,
    }


def getDbsJsonFilename(filename):
    path = Path(filename)
    return path.with_stem(f"{path.stem}_dbs")

if __name__ == "__main__":
    jsonArg = sys.argv[-1]
    extraArgs = sys.argv[1:-1]


    print(f"args = {jsonArg} {extraArgs}")

    # Output JSON
    dbsJsonFilename = getDbsJsonFilename(jsonArg)
    dbsJson = {}

    # Load the JSON data from the input file.
    with open(jsonArg, "r") as file:
        data = json.load(file)

    validate_input_json(data)

    # Iterate over the jobs and create a DBS job.
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

        jobTitle = job["outputs"][0]
        dbsJson[jobTitle] = dbsJobOject(
            " ".join(command), job["inputs"] + data["common"]["inputs"] + mappingFileList
        )

    # Remove all output files. DBS had problem with renaming a file
    # if a destination file already exist. Check with SN-DBS team if
    # this problem has been fixed. If so, get rid of this code.
    # Removing files might be extremely slow on the machines with security
    # software installed.
    for job in data["jobs"]:
        for file in job["outputs"]:
            Path(file).unlink(missing_ok=True)

    with open(dbsJsonFilename, "w") as dbsJsonFile:
        dbsJsonFile.write(json.dumps({"jobs": dbsJson}, indent=4))
    tempFiles.append(dbsJsonFilename)

    # Execute the script with the provided JSON script and other arguments
    execute_script(dbsJsonFilename, extraArgs)

    # Remove all temporary files.
    for f in tempFiles:
        Path(f).unlink(missing_ok=True)
