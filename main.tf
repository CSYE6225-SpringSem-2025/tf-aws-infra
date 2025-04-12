terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
  required_version = ">= 1.0.0"
}

provider "aws" {
  region  = var.aws_region
  profile = "saurabhdemo"
}

# KMS Key for EC2 encryption
# resource "aws_kms_key" "ec2_key" {
#   description             = "KMS key for EC2 encryption"
#   deletion_window_in_days = 30
#   enable_key_rotation     = true

#   tags = {
#     Name        = "ec2-encryption-key"
#     Environment = var.environment
#   }
# }

# Add this data source at the top of your file
data "aws_caller_identity" "current" {}

# Replace your existing EC2 KMS key resource with this enhanced version
resource "aws_kms_key" "ec2_key" {
  description             = "KMS key for EC2 encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  is_enabled              = true  # Explicitly enable the key
  
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "Enable IAM User Permissions",
        Effect = "Allow",
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        },
        Action   = "kms:*",
        Resource = "*"
      },
      {
        Sid    = "Allow EC2 service to use the key",
        Effect = "Allow",
        Principal = {
          Service = "ec2.amazonaws.com"
        },
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ],
        Resource = "*"
      },
      {
        Sid    = "Allow autoscaling to use the key",
        Effect = "Allow",
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
        },
        Action = [
          "kms:CreateGrant",
          "kms:ListGrants",
          "kms:RevokeGrant",
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ],
        Resource = "*"
      },
      {
        Sid    = "Allow attachment of persistent resources",
        Effect = "Allow",
        Principal = {
          AWS = "*"
        },
        Action = [
          "kms:CreateGrant",
          "kms:ListGrants",
          "kms:RevokeGrant"
        ],
        Resource = "*",
        Condition = {
          Bool = {
            "kms:GrantIsForAWSResource": "true"
          }
        }
      }
    ]
  })

  tags = {
    Name        = "ec2-encryption-key"
    Environment = var.environment
  }
}

# KMS Key alias for EC2
resource "aws_kms_alias" "ec2_key_alias" {
  name          = "alias/${var.environment}-ec2-key"
  target_key_id = aws_kms_key.ec2_key.key_id
}

# KMS Key for RDS encryption
resource "aws_kms_key" "rds_key" {
  description             = "KMS key for RDS encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name        = "rds-encryption-key"
    Environment = var.environment
  }
}

# KMS Key alias for RDS
resource "aws_kms_alias" "rds_key_alias" {
  name          = "alias/${var.environment}-rds-key"
  target_key_id = aws_kms_key.rds_key.key_id
}

# KMS Key for S3 encryption
resource "aws_kms_key" "s3_key" {
  description             = "KMS key for S3 encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name        = "s3-encryption-key"
    Environment = var.environment
  }
}

# KMS Key alias for S3
resource "aws_kms_alias" "s3_key_alias" {
  name          = "alias/${var.environment}-s3-key"
  target_key_id = aws_kms_key.s3_key.key_id
}

# KMS Key for Secrets Manager
resource "aws_kms_key" "secrets_key" {
  description             = "KMS key for Secrets Manager encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name        = "secrets-encryption-key"
    Environment = var.environment
  }
}

# KMS Key alias for Secrets Manager
resource "aws_kms_alias" "secrets_key_alias" {
  name          = "alias/${var.environment}-secrets-key"
  target_key_id = aws_kms_key.secrets_key.key_id
}

# Data source for AZs
data "aws_availability_zones" "available" {
  state = "available"
}

# Data source for the custom AMI
data "aws_ami" "custom_app_ami" {
  owners = ["self"]

  filter {
    name   = "image-id"
    values = ["ami-0ae4d60b84a0b35ba"]
  }
}

# Random password for database
resource "random_password" "db_password" {
  length           = 16
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

# Secrets Manager secret for database password
resource "aws_secretsmanager_secret" "db_password_secret" {
  name                    = "${var.environment}/database/password"
  kms_key_id              = aws_kms_key.secrets_key.arn
  recovery_window_in_days = 0

  tags = {
    Name        = "database-password-secret"
    Environment = var.environment
  }
}

# Store the database password in Secrets Manager
resource "aws_secretsmanager_secret_version" "db_password_version" {
  secret_id     = aws_secretsmanager_secret.db_password_secret.id
  secret_string = random_password.db_password.result
}

# VPC
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = var.vpc_name
    Environment = var.environment
  }
}

# Internet Gateway
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name        = "${var.vpc_name}-igw"
    Environment = var.environment
  }
}

# Public Subnets
resource "aws_subnet" "public" {
  count             = length(var.public_subnet_cidrs)
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.public_subnet_cidrs[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]

  map_public_ip_on_launch = true

  tags = {
    Name        = "${var.vpc_name}-public-${count.index + 1}"
    Environment = var.environment
  }
}

# Private Subnets
resource "aws_subnet" "private" {
  count             = length(var.private_subnet_cidrs)
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name        = "${var.vpc_name}-private-${count.index + 1}"
    Environment = var.environment
  }
}

# Public Route Table
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name        = "${var.vpc_name}-public-rt"
    Environment = var.environment
  }
}

# Private Route Table
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name        = "${var.vpc_name}-private-rt"
    Environment = var.environment
  }
}

# Route Table Associations
resource "aws_route_table_association" "public" {
  count          = length(var.public_subnet_cidrs)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  count          = length(var.private_subnet_cidrs)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# Load Balancer Security Group
resource "aws_security_group" "lb_sg" {
  name        = "load-balancer-security-group"
  description = "Security group for application load balancer"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP access from anywhere"
  }

  # SSL/HTTPS ingress rule - commented out until SSL cert is available
  # ingress {
  #   from_port   = 443
  #   to_port     = 443
  #   protocol    = "tcp"
  #   cidr_blocks = ["0.0.0.0/0"]
  #   description = "HTTPS access from anywhere"
  # }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  tags = {
    Name        = "load-balancer-security-group"
    Environment = var.environment
  }
}

# Application Security Group
resource "aws_security_group" "app_sg" {
  name        = "application-security-group"
  description = "Security group for web application instances"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH access"
  }

  ingress {
    from_port       = var.app_port
    to_port         = var.app_port
    protocol        = "tcp"
    security_groups = [aws_security_group.lb_sg.id]
    description     = "Application port access from load balancer"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  tags = {
    Name        = "application-security-group"
    Environment = var.environment
  }
}

# Database Security Group
resource "aws_security_group" "db_sg" {
  name        = "database-security-group"
  description = "Security group for RDS instances"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = var.db_port
    to_port         = var.db_port
    protocol        = "tcp"
    security_groups = [aws_security_group.app_sg.id]
    description     = "Database port access from application"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  tags = {
    Name        = "database-security-group"
    Environment = var.environment
  }
}

# S3 Bucket with UUID name
resource "random_uuid" "bucket_uuid" {}

resource "aws_s3_bucket" "app_bucket" {
  bucket        = random_uuid.bucket_uuid.result
  force_destroy = true # Allow Terraform to delete bucket even if not empty

  tags = {
    Name        = "application-files-bucket"
    Environment = var.environment
  }
}

# S3 Bucket encryption with KMS
resource "aws_s3_bucket_server_side_encryption_configuration" "bucket_encryption" {
  bucket = aws_s3_bucket.app_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.s3_key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

# S3 Bucket lifecycle policy
resource "aws_s3_bucket_lifecycle_configuration" "bucket_lifecycle" {
  bucket = aws_s3_bucket.app_bucket.id

  rule {
    id     = "transition-to-ia"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
  }
}

# Make the bucket private
resource "aws_s3_bucket_public_access_block" "bucket_access" {
  bucket = aws_s3_bucket.app_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# DB Subnet Group
resource "aws_db_subnet_group" "db_subnet_group" {
  name       = "csye6225-db-subnet-group"
  subnet_ids = aws_subnet.private[*].id

  tags = {
    Name        = "CSYE6225 DB Subnet Group"
    Environment = var.environment
  }
}

# RDS Parameter Group
resource "aws_db_parameter_group" "db_parameter_group" {
  name   = "csye6225-db-parameter-group"
  family = var.db_parameter_group_family

  tags = {
    Name        = "CSYE6225 DB Parameter Group"
    Environment = var.environment
  }
}

# RDS Instance with KMS encryption
resource "aws_db_instance" "csye6225_db" {
  identifier             = "csye6225"
  engine                 = var.db_engine
  engine_version         = var.db_engine_version
  instance_class         = var.db_instance_class
  allocated_storage      = 20
  db_name                = "webapp"
  username               = "csye6225"
  password               = random_password.db_password.result
  parameter_group_name   = aws_db_parameter_group.db_parameter_group.name
  db_subnet_group_name   = aws_db_subnet_group.db_subnet_group.name
  vpc_security_group_ids = [aws_security_group.db_sg.id]
  publicly_accessible    = false
  multi_az               = false
  skip_final_snapshot    = true
  storage_encrypted      = true
  kms_key_id             = aws_kms_key.rds_key.arn

  tags = {
    Name        = "CSYE6225 Database"
    Environment = var.environment
  }
}

# IAM Role for EC2 to access S3
resource "aws_iam_role" "ec2_s3_role" {
  name = "ec2_s3_access_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = "EC2 S3 Access Role"
    Environment = var.environment
  }
}

# IAM Policy for S3 access
resource "aws_iam_policy" "s3_access_policy" {
  name        = "s3_access_policy"
  description = "Policy for EC2 instance to access S3 bucket"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Effect = "Allow"
        Resource = [
          aws_s3_bucket.app_bucket.arn,
          "${aws_s3_bucket.app_bucket.arn}/*"
        ]
      }
    ]
  })
}

# IAM Policy for Secrets Manager access
resource "aws_iam_policy" "secrets_access_policy" {
  name        = "secrets_access_policy"
  description = "Policy for EC2 instance to access Secrets Manager"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Effect   = "Allow"
        Resource = aws_secretsmanager_secret.db_password_secret.arn
      }
    ]
  })
}

# KMS access policy for EC2
resource "aws_iam_policy" "kms_access_policy" {
  name        = "kms_access_policy"
  description = "Policy for EC2 instance to use KMS keys"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Effect = "Allow"
        Resource = [
          aws_kms_key.ec2_key.arn,
          aws_kms_key.s3_key.arn,
          aws_kms_key.rds_key.arn,
          aws_kms_key.secrets_key.arn
        ]
      }
    ]
  })
}

# Attach policies to role
resource "aws_iam_role_policy_attachment" "s3_policy_attachment" {
  role       = aws_iam_role.ec2_s3_role.name
  policy_arn = aws_iam_policy.s3_access_policy.arn
}

resource "aws_iam_role_policy_attachment" "kms_policy_attachment" {
  role       = aws_iam_role.ec2_s3_role.name
  policy_arn = aws_iam_policy.kms_access_policy.arn
}

resource "aws_iam_role_policy_attachment" "secrets_policy_attachment" {
  role       = aws_iam_role.ec2_s3_role.name
  policy_arn = aws_iam_policy.secrets_access_policy.arn
}

# EC2 Instance Profile
resource "aws_iam_instance_profile" "ec2_profile" {
  name = "ec2_instance_profile"
  role = aws_iam_role.ec2_s3_role.name
}

# CloudWatch IAM Policy
resource "aws_iam_policy" "cloudwatch_policy" {
  name        = "cloudwatch_access_policy"
  description = "Policy for EC2 instance to access CloudWatch for logging and metrics"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "cloudwatch:PutMetricData",
          "ec2:DescribeVolumes",
          "ec2:DescribeTags",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams",
          "logs:DescribeLogGroups",
          "logs:CreateLogStream",
          "logs:CreateLogGroup"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })

  tags = {
    Name        = "CloudWatch Access Policy"
    Environment = var.environment
  }
}

# Attach CloudWatch policy to EC2 role
resource "aws_iam_role_policy_attachment" "cloudwatch_policy_attachment" {
  role       = aws_iam_role.ec2_s3_role.name
  policy_arn = aws_iam_policy.cloudwatch_policy.arn
}

# Application Load Balancer
resource "aws_lb" "app_lb" {
  name               = "app-load-balancer"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.lb_sg.id]
  subnets            = aws_subnet.public[*].id

  enable_deletion_protection = false

  tags = {
    Name        = "application-load-balancer"
    Environment = var.environment
  }
}

# Target Group for Load Balancer
resource "aws_lb_target_group" "app_tg" {
  name     = "app-target-group"
  port     = var.app_port
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id

  health_check {
    enabled             = true
    healthy_threshold   = 3
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
    path                = "/"
    port                = "traffic-port"
    protocol            = "HTTP"
  }

  tags = {
    Name        = "app-target-group"
    Environment = var.environment
  }
}

# Load Balancer HTTP Listener
resource "aws_lb_listener" "app_listener" {
  load_balancer_arn = aws_lb.app_lb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app_tg.arn
  }
}

# SSL certificate ARN variable - commented out until certificate is available
# variable "ssl_certificate_arn" {
#   description = "ARN of the imported SSL certificate"
#   type        = string
#   default     = ""
# }

# Load Balancer HTTPS Listener - commented out until certificate is available
# resource "aws_lb_listener" "https_listener" {
#   load_balancer_arn = aws_lb.app_lb.arn
#   port              = 443
#   protocol          = "HTTPS"
#   ssl_policy        = "ELBSecurityPolicy-2016-08"
#   certificate_arn   = var.ssl_certificate_arn
#
#   default_action {
#     type             = "forward"
#     target_group_arn = aws_lb_target_group.app_tg.arn
#   }
# }

# Launch Template for Auto Scaling Group with KMS encryption
resource "aws_launch_template" "app_launch_template" {
  name          = "app-launch-template"  # Changed from "csye6225_asg" for consistency
  image_id      = var.ami_id
  instance_type = var.instance_type
  key_name      = var.key_name

  block_device_mappings {
    device_name = "/dev/sda1"

    ebs {
      volume_size           = 25
      volume_type           = "gp2"
      delete_on_termination = true
      encrypted             = true
      kms_key_id            = aws_kms_key.ec2_key.arn
    }
  }

  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [aws_security_group.app_sg.id]
  }

  iam_instance_profile {
    name = aws_iam_instance_profile.ec2_profile.name
  }

  user_data = base64encode(<<-EOF
#!/bin/bash

# Create environment file for application
cat > /etc/environment <<EOL
DB_HOST=${aws_db_instance.csye6225_db.address}
DB_PORT=${var.db_port}
DB_NAME=${aws_db_instance.csye6225_db.db_name}
DB_USER=${aws_db_instance.csye6225_db.username}
DB_PASSWORD=${aws_db_instance.csye6225_db.password}
S3_BUCKET=${aws_s3_bucket.app_bucket.bucket}
AWS_REGION=${var.aws_region}
EOL

# Set proper permissions
chmod 644 /etc/environment

# Reload environment variables
source /etc/environment

# Create log directory if it doesn't exist
mkdir -p /var/log/webapp
chmod 755 /var/log/webapp
chown saurabh_user:saurabh_group /var/log/webapp

# # Start CloudWatch agent
# echo "Starting CloudWatch agent..."
# systemctl enable amazon-cloudwatch-agent
# systemctl restart amazon-cloudwatch-agent

# # Ensure the webapp service starts automatically
# systemctl enable webapp
# systemctl restart webapp

# # Print status for troubleshooting purposes
# echo "CloudWatch agent status:"
# systemctl status amazon-cloudwatch-agent --no-pager

# echo "Webapp service status:"
# systemctl status webapp --no-pager

# sudo systemctl restart webapp.service

# echo "EC2 user data script completed"
EOF
  )

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name        = "webapp-instance"
      Environment = var.environment
    }
  }

  tags = {
    Name        = "app-launch-template"
    Environment = var.environment
  }

  depends_on = [ aws_kms_key.ec2_key, aws_db_instance.csye6225_db, aws_s3_bucket.app_bucket ]
}

# Auto Scaling Group
resource "aws_autoscaling_group" "app_asg" {
  name             = "app-auto-scaling-group"  # Removed "-new" suffix
  min_size         = 1
  max_size         = 2
  desired_capacity = 2

  vpc_zone_identifier = aws_subnet.public[*].id
  target_group_arns   = [aws_lb_target_group.app_tg.arn]

  launch_template {
    id      = aws_launch_template.app_launch_template.id
    version = "$Latest"
  }

  default_cooldown = 60

  tag {
    key                 = "Name"
    value               = "webapp-asg-instance"
    propagate_at_launch = true
  }

  tag {
    key                 = "Environment"
    value               = var.environment
    propagate_at_launch = true
  }
  
  depends_on = [ aws_launch_template.app_launch_template ]
}

# Auto Scaling Policies
resource "aws_autoscaling_policy" "scale_up" {
  name                   = "scale-up-policy"
  autoscaling_group_name = aws_autoscaling_group.app_asg.name
  adjustment_type        = "ChangeInCapacity"
  scaling_adjustment     = 1
  cooldown               = 60
}

resource "aws_autoscaling_policy" "scale_down" {
  name                   = "scale-down-policy"
  autoscaling_group_name = aws_autoscaling_group.app_asg.name
  adjustment_type        = "ChangeInCapacity"
  scaling_adjustment     = -1
  cooldown               = 60
}

# CloudWatch Alarms for Auto Scaling
resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  alarm_name          = "high-cpu-usage"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  threshold           = 18
  alarm_description   = "Scale up when CPU exceeds 18%"

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.app_asg.name
  }

  alarm_actions = [aws_autoscaling_policy.scale_up.arn]
}

resource "aws_cloudwatch_metric_alarm" "low_cpu" {
  alarm_name          = "low-cpu-usage"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 10
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  threshold           = 12
  alarm_description   = "Scale down when CPU is below 12%"

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.app_asg.name
  }

  alarm_actions = [aws_autoscaling_policy.scale_down.arn]
}

# Route53 Record to point to Load Balancer
resource "aws_route53_record" "app_dns" {
  zone_id = var.route53_zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = aws_lb.app_lb.dns_name
    zone_id                = aws_lb.app_lb.zone_id
    evaluate_target_health = true
  }
}