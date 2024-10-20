import json

def convert_to_sonar_format(sarif_file, output_file, engine_id):
    with open(sarif_file, 'r') as f:
        sarif_data = json.load(f)

    sonar_output = {
        "issues": []
    }

    for run in sarif_data.get("runs", []):
        for result in run.get("results", []):
            for location in result.get("locations", []):
                severity = result.get("level", "WARNING").upper()
                if severity not in ["INFO", "MINOR", "MAJOR", "CRITICAL", "BLOCKER"]:
                    severity = "MAJOR"  # Default to MAJOR if an invalid severity is found

                issue_data = {
                    "engineId": engine_id,
                    "ruleId": result.get("ruleId", ""),
                    "severity": severity,
                    "type": "VULNERABILITY",  # Customize based on the type of issue
                    "primaryLocation": {
                        "message": result.get("message", {}).get("text", ""),
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

# Convert Checkov and TFSec SARIF files to SonarQube-compatible format
convert_to_sonar_format('results_sarif.sarif', 'checkov-sonarqube.json', 'checkov')
convert_to_sonar_format('tfsec.sarif', 'tfsec-sonarqube.json', 'tfsec')
