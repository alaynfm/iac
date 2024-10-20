variable "name" {
  description = "the name of your stack"
}

variable "environment" {
  description = "the name of your environment"
}

variable "cidr" {
  description = "The CIDR block for the VPC."
}

variable "public_subnets" {
  description = "List of public subnets"
}

variable "private_subnets" {
  description = "List of private subnets"
}

variable "private_deploy_subnets" {
  description = "List of private subnet to deploy apps in eks"
}

variable "availability_zones" {
  description = "List of availability zones"
}