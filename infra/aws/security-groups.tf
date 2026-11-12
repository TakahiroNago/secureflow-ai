# Who may talk to whom. The load balancer is the only thing the internet reaches; the host accepts port 80 from the
# load balancer's group alone (docs/security-design.md §22 A-2: X-Forwarded-For is trusted from the VPC's range
# because only the load balancer can connect from it).

resource "aws_security_group" "alb" {
  name        = "${var.project}-alb"
  description = "SecureFlow load balancer: HTTPS and HTTP from the internet, port 80 to the host"
  vpc_id      = aws_vpc.this.id

  tags = { Name = "${var.project}-alb" }
}

#trivy:ignore:AVD-AWS-0107 the public entry point of the service (D33); TLS ends here
resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  security_group_id = aws_security_group.alb.id
  description       = "HTTPS from anywhere"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

#trivy:ignore:AVD-AWS-0107 answered with a redirect to HTTPS only (alb.tf)
resource "aws_vpc_security_group_ingress_rule" "alb_http" {
  security_group_id = aws_security_group.alb.id
  description       = "HTTP from anywhere, redirected to HTTPS"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
}

resource "aws_vpc_security_group_egress_rule" "alb_to_host" {
  security_group_id            = aws_security_group.alb.id
  description                  = "To the host's nginx"
  referenced_security_group_id = aws_security_group.host.id
  ip_protocol                  = "tcp"
  from_port                    = 80
  to_port                      = 80
}

resource "aws_security_group" "host" {
  name        = "${var.project}-host"
  description = "SecureFlow host: port 80 from the load balancer only; no SSH (SSM Session Manager)"
  vpc_id      = aws_vpc.this.id

  tags = { Name = "${var.project}-host" }
}

resource "aws_vpc_security_group_ingress_rule" "host_from_alb" {
  security_group_id            = aws_security_group.host.id
  description                  = "nginx, from the load balancer"
  referenced_security_group_id = aws_security_group.alb.id
  ip_protocol                  = "tcp"
  from_port                    = 80
  to_port                      = 80
}

#trivy:ignore:AVD-AWS-0104 the AWS APIs (SSM, parameter store, S3, CloudWatch), GHCR and Docker's apt repository; no NAT gateway or VPC endpoint (D33)
resource "aws_vpc_security_group_egress_rule" "host_https" {
  security_group_id = aws_security_group.host.id
  description       = "HTTPS out: AWS APIs, image registry, package repositories"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

#trivy:ignore:AVD-AWS-0104 Ubuntu's package mirrors are plain HTTP; the packages are signed
resource "aws_vpc_security_group_egress_rule" "host_http" {
  security_group_id = aws_security_group.host.id
  description       = "HTTP out: Ubuntu package mirrors"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
}

resource "aws_vpc_security_group_egress_rule" "host_dns_udp" {
  security_group_id = aws_security_group.host.id
  description       = "DNS to the VPC resolver"
  cidr_ipv4         = var.vpc_cidr
  ip_protocol       = "udp"
  from_port         = 53
  to_port           = 53
}

resource "aws_vpc_security_group_egress_rule" "host_dns_tcp" {
  security_group_id = aws_security_group.host.id
  description       = "DNS to the VPC resolver (large answers)"
  cidr_ipv4         = var.vpc_cidr
  ip_protocol       = "tcp"
  from_port         = 53
  to_port           = 53
}
