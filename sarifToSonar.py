import json
import os

def convert_to_sonar_format(sarif_file):
    with open(sarif_file, 'r') as f:
        sarif_data = json.load(f)

    sonar_issues = []

    for run in sarif_data.get("runs", []):
        # Extract tool name from SARIF file
        engine_id = run.get("tool", {}).get("driver", {}).get("name", "unknown_tool")
        
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            message = result.get("message", {}).get("text", "")
            issue_type = "CODE_SMELL"  # Default issue type

            for location in result.get("locations", []):
                severity = result.get("level", "WARNING").upper()
                if severity not in ["INFO", "MINOR", "MAJOR", "CRITICAL", "BLOCKER"]:
                    severity = "MAJOR"  # Default to MAJOR if an invalid severity is found

                issue_data = {
                    "engineId": engine_id,
                    "ruleId": rule_id,
                    "severity": severity,
                    "type": issue_type,
                    "primaryLocation": {
                        "message": message,
                        "filePath": location.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", ""),
                        "textRange": {
                            "startLine": location.get("physicalLocation", {}).get("region", {}).get("startLine", 1),
                            "endLine": location.get("physicalLocation", {}).get("region", {}).get("endLine", 1)
                        }
                    }
                }
                sonar_issues.append(issue_data)

    return sonar_issues

def analyze_all_sarif_files_in_current_directory(output_file):
    all_issues = {
        "issues": []
    }

    # Get the current directory where the script is located
    current_directory = os.path.dirname(os.path.abspath(__file__))

    # Iterate over all .sarif files in the current directory
    for file in os.listdir(current_directory):
        if file.endswith(".sarif"):
            file_path = os.path.join(current_directory, file)
            print(f"Processing {file_path}")
            issues = convert_to_sonar_format(file_path)
            all_issues["issues"].extend(issues)

    # Write all issues to the final output file
    with open(output_file, 'w') as f:
        json.dump(all_issues, f, indent=2)

# Convert all SARIF files in the current directory to SonarQube-compatible format and combine into one output file
analyze_all_sarif_files_in_current_directory('all.json')