import json

def convert_to_sarif(sarif_file, output_file, engine_id):
    with open(sarif_file, 'r') as f:
        sarif_data = json.load(f)

    sarif_output = {
        "version": "2.1.0",
        "$schema": "http://json.schemastore.org/sarif-2.1.0-rtm.5",
        "runs": []
    }

    runs = {
        "tool": {
            "driver": {
                "name": engine_id,  # Engine name (e.g., Checkov, TFSec)
                "informationUri": "https://www.test-linter-url.com",  # Can be customized
                "version": "1.0.0"  # Version of the tool (customize as needed)
            }
        },
        "results": []
    }

    for run in sarif_data.get("runs", []):
        for result in run.get("results", []):
            for location in result.get("locations", []):
                result_data = {
                    "level": result.get("level", "warning"),  # Error level
                    "message": {
                        "text": result.get("message", {}).get("text", "")
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": location.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
                                },
                                "region": {
                                    "startLine": location.get("physicalLocation", {}).get("region", {}).get("startLine", 1),
                                    "startColumn": location.get("physicalLocation", {}).get("region", {}).get("startColumn", 1),
                                    "endLine": location.get("physicalLocation", {}).get("region", {}).get("endLine", 1),
                                    "endColumn": location.get("physicalLocation", {}).get("region", {}).get("endColumn", 1)
                                }
                            }
                        }
                    ],
                    "ruleId": result.get("ruleId", "")
                }
                runs["results"].append(result_data)
    
    sarif_output["runs"].append(runs)

    with open(output_file, 'w') as f:
        json.dump(sarif_output, f, indent=2)

# Convert Checkov and TFSec SARIF files to SonarQube format
convert_sarif_to_sonarqube('results_sarif.sarif', 'checkov-sonarqube.json', 'checkov')
convert_sarif_to_sonarqube('tfsec.sarif', 'tfsec-sonarqube.json', 'tfsec')
