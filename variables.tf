variable "ami_id" {
description = "The ID of the AMI to use for the EC2 instance"
type = string
default = null # Make it optional
}
variable "aws_region" {
description = "AWS region to deploy infrastructure"
type = string
default = "us-east-1"
}


variable "vpc_cidr" {
description = "CIDR block for the VPC"
type = string
default = "10.0.0.0/16"
}

variable "vpc_name" {
description = "Name of the VPC"
type = string
default = "csye6225-vpc"
}

variable "environment" {
description = "Environment (dev, staging, prod)"
type = string
default = "dev"
}

variable "public_subnet_cidrs" {
description = "CIDR blocks for the public subnets"
type = list(string)
default = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
}

variable "private_subnet_cidrs" {
description = "CIDR blocks for the private subnets"
type = list(string)
default = ["10.0.11.0/24", "10.0.12.0/24", "10.0.13.0/24"]
}

variable "instance_type" {
description = "EC2 instance type"
type = string
default = "t2.micro"
}

variable "root_volume_size" {
description = "Size of the root volume in GB"
type = number
default = 20
}

variable "root_volume_type" {
description = "Type of the root volume"
type = string
default = "gp2"
}

variable "app_port" {
description = "Port for the web application"
type = number
default = 8080
}

# Database configuration variables
variable "db_engine" {
description = "Database engine (mysql, mariadb, postgres)"
type = string
default = "mysql"
}

variable "db_engine_version" {
description = "Database engine version"
type = string
default = "8.0"
}

variable "db_parameter_group_family" {
description = "Database parameter group family"
type = string
default = "mysql8.0"
}

variable "db_instance_class" {
description = "Database instance class"
type = string
default = "db.t3.micro" # Cheapest option
}

variable "db_port" {
description = "Database port"
type = number
default = 3306 # For MySQL/MariaDB (use 5432 for PostgreSQL)
}

variable "db_password" {
description = "Database master password"
type = string
sensitive = true
}

