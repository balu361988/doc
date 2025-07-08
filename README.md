# 🧾 Hackathon DevOps Project Documentation
git-Token : - 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
git push origin main

......................................................................................
#pre-install
#Install AWS CLI
* sudo apt update
* sudo apt install unzip curl -y
* curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
* unzip awscliv2.zip
* sudo ./aws/install
* aws configure
AWS Access Key ID: AKIAVN72DC6EMU4SUCTL
AWS Secret Access Key: 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
Default region name: ap-south-1
.........................................................................................
#docker
sudo apt update
sudo apt install -y apt-transport-https ca-certificates curl software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update && sudo apt install docker-ce -y
sudo usermod -aG docker $USER
sudo systemctl status docker
docker --version
..............................................................................................................................................
#terraform
wget -O - https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(grep -oP '(?<=UBUNTU_CODENAME=).*' /etc/os-release || lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install terraform

## 📁 Project Structure (Monorepo)

mkdir -p /hackathon-devops/{appointment-service,patient-service,terraform/environments/{dev,prod,staging},terraform/modules/{alb,ecs,iam,network,securitygroup}



# Create empty files
touch {Dockerfile,index.js,package.json}
touch {Dockerfile,index.js,package.json}
touch {backend.tf,main.tf}


root/hackathon-devops/
├── appointment-service/
│   ├── Dockerfile
│   ├── index.js
│   └── package.json
├── patient-service/
│   ├── Dockerfile
│   ├── index.js
│   └── package.json
├── terraform/
│   ├── environments/
│   │   ├── dev/
│   │   │   ├── backend.tf
│   │   │   └── main.tf
│   │   ├── prod/
│   │   └── staging/
│   └── modules/
│       ├── alb/
│       ├── ecs/
│       ├── iam/
│       ├── network/
│       └── securitygroup/
└── .github/
    └── workflows/
        ├── appointment.yml
        └── patient.yml
---

## 📦 appointment-service

### Dockerfile
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 80
CMD ["npm", "start"]
...........................................................................
index.js
...................


const express = require('express');
const app = express();
const port = process.env.PORT || 80;
const host = '0.0.0.0';

app.get('/appointment', (req, res) => {
  res.send('✅ Appointment Service running on port 80!');
});

app.listen(port, host, () => {
  console.log(`✅ Appointment service running on http://${host}:${port}`);
});
...........................................................................
package.json
...........................................................................
  "name": "appointment-service",
  "version": "1.0.0",
  "main": "index.js",
  "scripts": {
    "start": "node index.js"
  },
  "dependencies": {
    "express": "^4.18.2"
  }
}
________________________________________
📦 patient-service
Dockerfile
.....................................

FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 80
CMD ["npm", "start"]
..............................................
index.js
.................................

const express = require('express');
const app = express();
const port = process.env.PORT || 80;
const host = '0.0.0.0';

app.get('/patient', (req, res) => {
  res.send('✅ Patient Service running on port 80!');
});

app.listen(port, host, () => {
  console.log(`✅ Patient service running on http://${host}:${port}`);
});
.......................................................................................................
package.json
.....................................................................................................
{
  "name": "patient-service",
  "version": "1.0.0",
  "main": "index.js",
  "scripts": {
    "start": "node index.js"
  },
  "dependencies": {
    "express": "^4.18.2"
  }
}
________________________________________
🧱 Terraform Structure
environments/dev/main.tf

provider "aws" {
  region = "ap-south-1"
}

module "network" {
  source               = "../../modules/network"
  env                  = "dev"
  vpc_cidr             = "10.0.0.0/16"
  public_subnet_cidrs  = ["10.0.1.0/24", "10.0.2.0/24"]
  private_subnet_cidrs = ["10.0.3.0/24", "10.0.4.0/24"]
  azs                  = ["ap-south-1a", "ap-south-1b"]
}

module "iam" {
  source         = "../../modules/iam"
  env            = "dev"
  aws_account_id = "373649774472"
}

module "sg" {
  source = "../../modules/securitygroup"
  env    = "dev"
  vpc_id = module.network.vpc_id
}

module "alb" {
  source            = "../../modules/alb"
  env               = "dev"
  vpc_id            = module.network.vpc_id
  public_subnet_ids = module.network.public_subnet_ids
  alb_sg_id         = module.sg.alb_sg_id
}

module "ecs" {
  source             = "../../modules/ecs"
  env                = "dev"
  region             = "ap-south-1"
  execution_role_arn = module.iam.ecs_task_execution_role_arn
  task_role_arn      = module.iam.ecs_task_role_arn
  patient_image      = "373649774472.dkr.ecr.ap-south-1.amazonaws.com/patient-service:latest"
  appointment_image  = "373649774472.dkr.ecr.ap-south-1.amazonaws.com/appointment-service:latest"
  private_subnet_ids = module.network.private_subnet_ids
  sg_id              = module.sg.ecs_sg_id
  patient_tg_arn     = module.alb.patient_tg_arn
  appointment_tg_arn = module.alb.appointment_tg_arn
}
........................................................................................
environments/dev/backend.tf
.............................................................................
terraform {
  backend "s3" {
    bucket         = "balu-terraform-backend"
    key            = "dev/terraform.tfstate"
    region         = "ap-south-1"
    dynamodb_table = "terraform-locks"
    encrypt        = true
  }
}
________________________________________
📁 Terraform Modules
________________________________________
modules/alb
main.tf
resource "aws_lb" "this" {
  name               = "${var.env}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [var.alb_sg_id]
  subnets            = var.public_subnet_ids
  enable_deletion_protection = false

  tags = {
    Environment = var.env
  }
}

resource "aws_lb_target_group" "patient" {
  name        = "${var.env}-tg-patient"
  port        = 80
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = var.vpc_id

  health_check {
    path                = "/patient"
    protocol            = "HTTP"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
    matcher             = "200-399"
  }
}

resource "aws_lb_target_group" "appointment" {
  name        = "${var.env}-tg-appointment"
  port        = 80
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = var.vpc_id

  health_check {
    path                = "/appointment"
    protocol            = "HTTP"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
    matcher             = "200-399"
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "Default ALB response"
      status_code  = "200"
    }
  }
}

resource "aws_lb_listener_rule" "patient_rule" {
  listener_arn = aws_lb_listener.http.arn
  priority     = 100

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.patient.arn
  }

  condition {
    path_pattern {
      values = ["/patient*"]
    }
  }
}

resource "aws_lb_listener_rule" "appointment_rule" {
  listener_arn = aws_lb_listener.http.arn
  priority     = 200

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.appointment.arn
  }

  condition {
    path_pattern {
      values = ["/appointment*"]
    }
  }
}
........................................................................................................
outputs.tf
...........................................................................................................
output "alb_dns_name" {
  value = aws_lb.this.dns_name
}

output "patient_target_group_arn" {
  value = aws_lb_target_group.patient.arn
}

output "appointment_target_group_arn" {
  value = aws_lb_target_group.appointment.arn
}

output "patient_tg_arn" {
  value = aws_lb_target_group.patient.arn
}

output "appointment_tg_arn" {
  value = aws_lb_target_group.appointment.arn
}
.......................................................................................................
variables.tf
........................................................................................................
variable "env" {}
variable "vpc_id" {}
variable "public_subnet_ids" {
  type = list(string)
}
variable "alb_sg_id" {}
..........................................................................................
modules/ecs
.................................................................................................
main.tf
resource "aws_ecs_cluster" "this" {
  name = "${var.env}-ecs-cluster"
}

resource "aws_cloudwatch_log_group" "patient" {
  name              = "/ecs/patient"
  retention_in_days = 7
  tags = {
    Name = "patient-log-group"
  }
}

resource "aws_cloudwatch_log_group" "appointment" {
  name              = "/ecs/appointment"
  retention_in_days = 7
  tags = {
    Name = "appointment-log-group"
  }
}

resource "aws_ecs_task_definition" "patient" {
  family                   = "patient-task"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = var.execution_role_arn
  task_role_arn            = var.task_role_arn

  container_definitions = jsonencode([{
    name      = "patient"
    image     = var.patient_image
    portMappings = [{
      containerPort = 80
      protocol      = "tcp"
    }]
    essential = true
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = "/ecs/patient"
        awslogs-region        = var.region
        awslogs-stream-prefix = "ecs"
      }
    }
  }])
}

resource "aws_ecs_service" "patient" {
  name            = "patient-service"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.patient.arn
  launch_type     = "FARGATE"
  desired_count   = 1

  load_balancer {
    target_group_arn = var.patient_tg_arn
    container_name   = "patient"
    container_port   = 80
  }

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [var.sg_id]
    assign_public_ip = false
  }

  depends_on = [
    aws_ecs_task_definition.patient,
    aws_cloudwatch_log_group.patient
  ]
}

resource "aws_ecs_task_definition" "appointment" {
  family                   = "appointment-task"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = var.execution_role_arn
  task_role_arn            = var.task_role_arn

  container_definitions = jsonencode([{
    name      = "appointment"
    image     = var.appointment_image
    portMappings = [{
      containerPort = 80
      protocol      = "tcp"
    }]
    essential = true
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = "/ecs/appointment"
        awslogs-region        = var.region
        awslogs-stream-prefix = "ecs"
      }
    }
  }])
}

resource "aws_ecs_service" "appointment" {
  name            = "appointment-service"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.appointment.arn
  launch_type     = "FARGATE"
  desired_count   = 1

  load_balancer {
    target_group_arn = var.appointment_tg_arn
    container_name   = "appointment"
    container_port   = 80
  }

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [var.sg_id]
    assign_public_ip = true
  }

  depends_on = [
    aws_ecs_task_definition.appointment,
    aws_cloudwatch_log_group.appointment
  ]
}
............................................................................................................
outputs.tf
..............................................................................................................
output "ecs_cluster_id" {
  value = aws_ecs_cluster.this.id
}
.................................................................................................
variables.tf
....................................................................................................
variable "env" {}
variable "region" {}
variable "execution_role_arn" {}
variable "task_role_arn" {}
variable "patient_image" {}
variable "appointment_image" {}
variable "private_subnet_ids" {
  type = list(string)
}
variable "sg_id" {}
variable "patient_tg_arn" {
  description = "Target group ARN for patient service"
  type        = string
}
variable "appointment_tg_arn" {
  description = "Target group ARN for appointment service"
  type        = string
}
...........................................................................................................................
modules/iam
..........................................................................................................................
main.tf
resource "aws_iam_role" "ecs_task_execution_role" {
  name = "${var.env}-ecs-task-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        },
        Effect = "Allow",
        Sid    = ""
      }
    ]
  })

  tags = {
    Name = "${var.env}-ecs-task-execution-role"
  }
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution_policy" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_policy" "ecs_logs_scoped_policy" {
  name = "${var.env}-ecs-logs-scoped"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = ["logs:CreateLogGroup"],
        Resource = [
          "arn:aws:logs:ap-south-1:${var.aws_account_id}:log-group:/ecs/patient-service:*",
          "arn:aws:logs:ap-south-1:${var.aws_account_id}:log-group:/ecs/appointment-service:*"
        ]
      },
      {
        Effect = "Allow",
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Resource = [
          "arn:aws:logs:ap-south-1:${var.aws_account_id}:log-group:/ecs/patient-service:*",
          "arn:aws:logs:ap-south-1:${var.aws_account_id}:log-group:/ecs/appointment-service:*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_logs_scoped" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = aws_iam_policy.ecs_logs_scoped_policy.arn
}

resource "aws_iam_role" "ecs_task_role" {
  name = "${var.env}-ecs-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        },
        Effect = "Allow",
        Sid    = ""
      }
    ]
  })

  tags = {
    Name = "${var.env}-ecs-task-role"
  }
}
..................................................................................................................................
outputs.tf
.................................................................................................................................
output "ecs_task_execution_role_arn" {
  value = aws_iam_role.ecs_task_execution_role.arn
}

output "ecs_task_role_arn" {
  value = aws_iam_role.ecs_task_role.arn
}
..................................................................................................
variables.tf
................................................................................................
variable "env" {
  type        = string
  description = "Environment name"
}
variable "aws_account_id" {
  description = "Your AWS account ID"
  type        = string
}
________________________________________
modules/network
main.tf
...................................................................
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = {
    Name = "${var.env}-vpc"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = "${var.env}-igw"
  }
}

resource "aws_subnet" "public" {
  count                   = length(var.public_subnet_cidrs)
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = element(var.azs, count.index)
  map_public_ip_on_launch = true
  tags = {
    Name = "${var.env}-public-subnet-${count.index + 1}"
  }
}

resource "aws_subnet" "private" {
  count             = length(var.private_subnet_cidrs)
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = element(var.azs, count.index)
  tags = {
    Name = "${var.env}-private-subnet-${count.index + 1}"
  }
}

resource "aws_eip" "nat" {}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id
  tags = {
    Name = "${var.env}-nat"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = "${var.env}-public-rt"
  }
}

resource "aws_route" "public_internet_access" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.igw.id
}

resource "aws_route_table_association" "public" {
  count          = length(aws_subnet.public)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = "${var.env}-private-rt"
  }
}

resource "aws_route" "private_nat_gateway" {
  route_table_id         = aws_route_table.private.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.nat.id
}

resource "aws_route_table_association" "private" {
  count          = length(aws_subnet.private)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}
.........................................................................................
outputs.tf
...................................................................................
output "vpc_id" {
  value = aws_vpc.main.id
}

output "public_subnet_ids" {
  value = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  value = aws_subnet.private[*].id
}
..................................................................................
variables.tf
................................................................................
variable "vpc_cidr" {
  type        = string
  description = "VPC CIDR block"
}

variable "public_subnet_cidrs" {
  type        = list(string)
  description = "List of public subnet CIDRs"
}

variable "private_subnet_cidrs" {
  type        = list(string)
  description = "List of private subnet CIDRs"
}

variable "azs" {
  type        = list(string)
  description = "Availability zones"
}

variable "env" {
  type        = string
  description = "Environment name (dev/staging/prod)"
}
________________________________________
modules/securitygroup
main.tf
....................................................................................
resource "aws_security_group" "alb_sg" {
  name        = "${var.env}-alb-sg"
  description = "Allow HTTP traffic from internet"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.env}-alb-sg"
  }
}

resource "aws_security_group" "ecs_sg" {
  name        = "${var.env}-ecs-sg"
  description = "Allow traffic from ALB to ECS containers"
  vpc_id      = var.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.env}-ecs-sg"
  }
}

resource "aws_security_group_rule" "allow_alb_to_ecs" {
  type                     = "ingress"
  from_port                = 80
  to_port                  = 80
  protocol                 = "tcp"
  security_group_id        = aws_security_group.ecs_sg.id
  source_security_group_id = aws_security_group.alb_sg.id
  description              = "Allow HTTP from ALB to ECS"
}
..................................................................................................
outputs.tf
.................................................................................................
output "ecs_sg_id" {
  value = aws_security_group.ecs_sg.id
}

output "alb_sg_id" {
  value = aws_security_group.alb_sg.id
}
.......................................................................................................
variables.tf
........................................................................................................
variable "env" {
  description = "Environment"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID"
  type        = string
}
________________________________________


🚀 GitHub Actions Workflows
.github/workflows/appointment.yml
yaml
Copy
name: Build and Deploy Appointment Service
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      IMAGE_URI: ${{ secrets.ECR_REPO_APPOINTMENT }}:latest
    steps:
      - uses: actions/checkout@v3
      - uses: aws-actions/configure-aws-credentials@v2
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: ${{ secrets.AWS_REGION }}
      - run: |
          aws ecr get-login-password --region $AWS_REGION | \
          docker login --username AWS --password-stdin ${{ secrets.ECR_REPO_APPOINTMENT }}
      - run: |
          cd appointment-service
          docker build -t $IMAGE_URI .
          docker push $IMAGE_URI
      - run: |
          aws ecs update-service \
            --cluster ${{ secrets.CLUSTER_NAME }} \
            --service ${{ secrets.APPOINTMENT_SERVICE_NAME }} \
            --force-new-deployment
.github/workflows/patient.yml
yaml
Copy
name: Build and Deploy Patient Service
on:
  push:
    branches: [main]
jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      IMAGE_URI: ${{ secrets.ECR_REPO_PATIENT }}:latest
    steps:
      - uses: actions/checkout@v3
      - uses: aws-actions/configure-aws-credentials@v2
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: ${{ secrets.AWS_REGION }}
      - run: |
          aws ecr get-login-password --region $AWS_REGION | \
          docker login --username AWS --password-stdin ${{ secrets.ECR_REPO_PATIENT }}
      - run: |
          cd patient-service
          docker build -t $IMAGE_URI .
          docker push $IMAGE_URI
      - run: |
          aws ecs update-service \
            --cluster ${{ secrets.CLUSTER_NAME }} \
            --service ${{ secrets.PATIENT_SERVICE_NAME }} \
            --force-new-deployment
________________________________________

