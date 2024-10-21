import json
import re


def convert_to_sonar_format(sarif_file, output_file, engine_id):
    with open(sarif_file, 'r') as f:
        sarif_data = json.load(f)

    sonar_output = {
        "issues": []
    }

    for run in sarif_data.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            message = result.get("message", {}).get("text", "")
            file_path = result.get("locations", [])[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")

            # Classify based on patterns
            issue_type = "CODE_SMELL"

            for location in result.get("locations", []):
                severity = result.get("level", "WARNING").upper()
                if severity not in ["INFO", "MINOR", "MAJOR", "CRITICAL", "BLOCKER"]:
                    severity = "MAJOR"  # Default to MAJOR if an invalid severity is found

                issue_data = {
                    "engineId": engine_id,
                    "ruleId": rule_id,
                    "severity": severity,
                    "type": issue_type,  # Set issue type to VULNERABILITY, BUG, or CODE_SMELL. It is going to be deprecated
                    "primaryLocation": {
                        "message": message,
                        "filePath": location.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", ""),
                        "textRange": {
                            "startLine": location.get("physicalLocation", {}).get("region", {}).get("startLine", 1),
                            "endLine": location.get("physicalLocation", {}).get("region", {}).get("endLine", 1)
                        }
                    }
                }
                sonar_output["issues"].append(issue_data)

    with open(output_file, 'w') as f:
        json.dump(sonar_output, f, indent=2)

# Convert SARIF files to SonarQube-compatible format with pattern-based classification
convert_to_sonar_format('results_sarif.sarif', 'checkov-sonarqube.json', 'checkov')
