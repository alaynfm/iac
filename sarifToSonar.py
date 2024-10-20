import json

# Function to convert new format into SonarQube-compatible format
def convert_to_sonar_format(new_format_file, output_file):
    with open(new_format_file, 'r') as f:
        new_format_data = json.load(f)

    sonar_output = {
        "issues": []
    }

    # Create a dictionary to map ruleId to its associated rule details
    rules_dict = {rule['id']: rule for rule in new_format_data['rules']}

    # Process each issue and map it to its corresponding rule details
    for issue in new_format_data.get("issues", []):
        rule_id = issue.get("ruleId", "")
        rule = rules_dict.get(rule_id, {})

        # If no rule is found for the issue, skip this issue
        if not rule:
            continue

        # Fetch the primary location details
        primary_location = issue.get("primaryLocation", {})
        file_path = primary_location.get("filePath", "")
        message = primary_location.get("message", "")
        text_range = primary_location.get("textRange", {})

        # Create a list to store all location data
        locations = [{
            "message": message,
            "filePath": file_path,
            "textRange": {
                "startLine": text_range.get("startLine", 1),
                "startColumn": text_range.get("startColumn", 1),
                "endLine": text_range.get("endLine", text_range.get("startLine", 1)),
                "endColumn": text_range.get("endColumn", 1)
            }
        }]

        # Process secondary locations if available
        for secondary_location in issue.get("secondaryLocations", []):
            secondary_file_path = secondary_location.get("filePath", "")
            secondary_message = secondary_location.get("message", "")
            secondary_text_range = secondary_location.get("textRange", {})

            locations.append({
                "message": secondary_message,
                "filePath": secondary_file_path,
                "textRange": {
                    "startLine": secondary_text_range.get("startLine", 1),
                    "startColumn": secondary_text_range.get("startColumn", 1),
                    "endLine": secondary_text_range.get("endLine", secondary_text_range.get("startLine", 1)),
                    "endColumn": secondary_text_range.get("endColumn", 1)
                }
            })

        # Extract the software quality impact and severity from the rule's impacts
        impacts = rule.get("impacts", [])
        for impact in impacts:
            issue_data = {
                "engineId": rule.get("engineId", ""),
                "ruleId": rule_id,
                "severity": impact.get("severity", "MAJOR").upper(),
                "type": impact.get("softwareQuality", "CODE_SMELL"),  # Map software quality to issue type
                "primaryLocation": {
                    "message": message,
                    "filePath": file_path,
                    "textRange": {
                        "startLine": text_range.get("startLine", 1),
                        "startColumn": text_range.get("startColumn", 1),
                        "endLine": text_range.get("endLine", text_range.get("startLine", 1)),
                        "endColumn": text_range.get("endColumn", 1)
                    }
                },
                "secondaryLocations": locations[1:]  # Secondary locations if available
            }

            # Append the issue data to the output list
            sonar_output["issues"].append(issue_data)

    # Write the SonarQube-compatible output to a JSON file
    with open(output_file, 'w') as f:
        json.dump(sonar_output, f, indent=2)

# Convert the new format JSON into SonarQube-compatible format
convert_to_sonar_format('new_format.json', 'sonarqube_compatible.json')
