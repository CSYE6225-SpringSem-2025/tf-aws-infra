variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1" 
}

variable "vpc_name" {
  description = "Name tag for the VPC"
  type        = string
  default     = "main-vpc"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
  default     = ["10.0.4.0/24", "10.0.5.0/24", "10.0.6.0/24"]
}

variable "environment" {
  description = "Environment tag (e.g., dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "app_port" {
  description = "Port on which the application runs"
  type        = number
  default     = 8080 
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t2.micro"
}
variable "ami_id" {
  description = "The ID of the AMI to use for the EC2 instance"
  type        = string
}
variable "root_volume_size" {
  description = "Size of the root EBS volume in gigabytes"
  type        = number
  default     = 25
}

variable "root_volume_type" {
  description = "Type of the root EBS volume (gp2, gp3, io1, io2, sc1, st1)"
  type        = string
  default     = "gp2"
}