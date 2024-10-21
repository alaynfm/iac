# Enable the AWS plugin for TFLint
plugin "aws" {
  enabled = true
  version = "latest"  # or specify the version, e.g., "0.48.0"
  region  = "us-east-1" # Set your default AWS region
}

# Enable rules to validate AWS resources, like DB instances
rule "aws_db_instance_invalid_class" {
  enabled = true       # Enables RDS instance class validation
}

# Optionally, you can enable other AWS resource validation rules
rule "aws_instance_invalid_type" {
  enabled = true       # Enables EC2 instance type validation
}