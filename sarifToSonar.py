import json
import re

# Function to classify the issue based on the rule_id, message, or file_path
def classify_issue_by_pattern(rule_id, message, file_path):
    # Pattern-based classification for Security (VULNERABILITY)
    if re.search(r"(encryption|KMS|IAM|public|secret|security group|access|rotation|restrict|VPC)", message, re.IGNORECASE):
        return "SECURITY"
    # Pattern-based classification for Reliability (BUG)
    elif re.search(r"(monitoring|logging|Multi-AZ|availability|upgrade|snapshot|backup|failover)", message, re.IGNORECASE):
        return "RELIABILITY"
    # Default classification as Maintainability (CODE_SMELL)
    else:
        return "MAINTAINABILITY"

# Function to convert SARIF to SonarQube's new external issues format
def convert_to_sonar_format(sarif_file, output_file, engine_id):
    with open(sarif_file, 'r') as f:
        sarif_data = json.load(f)

    sonar_output = {
        "rules": [],
        "issues": []
    }

    rules_added = set()

    for run in sarif_data.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            message = result.get("message", {}).get("text", "")
            file_path = result.get("locations", [])[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")

            # Classify based on patterns
            software_quality = classify_issue_by_pattern(rule_id, message, file_path)

            # Determine severity level
            severity = result.get("level", "WARNING").upper()
            if severity not in ["HIGH", "MEDIUM", "LOW"]:
                severity = "MEDIUM"  # Default to MEDIUM if severity is invalid

            # Add rule details if not already added
            if rule_id not in rules_added:
                rule_data = {
                    "id": rule_id,
                    "name": rule_id,  # You may change it based on your own rule names
                    "description": message,  # You can expand with more details if necessary
                    "engineId": engine_id,
                    "cleanCodeAttribute": "FORMATTED",  # Default Clean Code Attribute; you can change it
                    "impacts": [
                        {
                            "softwareQuality": software_quality,
                            "severity": severity
                        }
                    ]
                }
                sonar_output["rules"].append(rule_data)
                rules_added.add(rule_id)

            # Loop through all locations and generate issue data
            for location in result.get("locations", []):
                issue_data = {
                    "ruleId": rule_id,
                    "primaryLocation": {
                        "message": message,
                        "filePath": location.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", ""),
                        "textRange": {
                            "startLine": str(location.get("physicalLocation", {}).get("region", {}).get("startLine", 1)),
                            "endLine": str(location.get("physicalLocation", {}).get("region", {}).get("endLine", 1))
                        }
                    },
                    "effortMinutes": str(result.get("effortMinutes", 0))
                }

                # Secondary locations if they exist
                secondary_locations = []
                for secondary_location in result.get("secondaryLocations", []):
                    secondary_locations.append({
                        "message": secondary_location.get("message", ""),
                        "filePath": secondary_location.get("filePath", ""),
                        "textRange": {
                            "startLine": str(secondary_location.get("textRange", {}).get("startLine", 1)),
                            "endLine": str(secondary_location.get("textRange", {}).get("endLine", 1))
                        }
                    })
                if secondary_locations:
                    issue_data["secondaryLocations"] = secondary_locations

                # Add issue to the list
                sonar_output["issues"].append(issue_data)

    # Write the final output to the JSON file
    with open(output_file, 'w') as f:
        json.dump(sonar_output, f, indent=2)

# Example usage: Convert SARIF files to SonarQube-compatible format
convert_to_sonar_format('results_sarif.sarif', 'sonarqube_external_issues.json', 'checkov')
