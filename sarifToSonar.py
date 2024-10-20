import json

def convert_sarif_to_sonarqube(sarif_file, output_file, engine_id):
    with open(sarif_file, 'r') as f:
        sarif_data = json.load(f)
    
    issues = []
    for run in sarif_data.get("runs", []):
        for result in run.get("results", []):
            for location in result.get("locations", []):
                issue = {
                    "engineId": engine_id,
                    "ruleId": result.get("ruleId", ""),
                    "severity": "CRITICAL" if result.get("level", "") == "error" else "MAJOR",
                    "type": "VULNERABILITY",
                    "primaryLocation": {
                        "message": result.get("message", {}).get("text", ""),
                        "filePath": location.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", ""),
                        "textRange": {
                            "startLine": location.get("physicalLocation", {}).get("region", {}).get("startLine", 1),
                            "endLine": location.get("physicalLocation", {}).get("region", {}).get("endLine", 1)
                        }
                    }
                }
                issues.append(issue)
    
    sonarqube_data = {"issues": issues}
    
    with open(output_file, 'w') as f:
        json.dump(sonarqube_data, f, indent=2)

# Convert Checkov and TFSec SARIF files to SonarQube format
convert_sarif_to_sonarqube('results_sarif.sarif', 'checkov-sonarqube.json', 'checkov')
convert_sarif_to_sonarqube('tfsec.sarif', 'tfsec-sonarqube.json', 'tfsec')
