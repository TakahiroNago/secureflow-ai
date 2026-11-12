# The entry point: an internet-facing application load balancer that ends TLS with an ACM certificate and forwards
# plain HTTP to the host's port 80 (docs/security-design.md §22 A-1). HTTP is redirected to HTTPS. Requests for any
# host name but the public one get 421: the load balancer's own name is not a way to reach the application.
#
# The certificate is validated by DNS. On the first apply enable_https is false: the certificate is requested and
# the CNAME to create at the DNS provider is in the outputs. Once it exists, enable_https = true makes the next apply
# wait for the validation and create the HTTPS listener (docs/operations.md §6.2).

resource "aws_acm_certificate" "this" {
  domain_name       = var.public_host
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = { Name = var.public_host }
}

resource "aws_acm_certificate_validation" "this" {
  count = var.enable_https ? 1 : 0

  certificate_arn = aws_acm_certificate.this.arn

  timeouts {
    create = "60m"
  }
}

#trivy:ignore:AVD-AWS-0053 the public entry point of the service (D33)
resource "aws_lb" "this" {
  name                       = var.project
  load_balancer_type         = "application"
  internal                   = false
  security_groups            = [aws_security_group.alb.id]
  subnets                    = aws_subnet.public[*].id
  drop_invalid_header_fields = true
  idle_timeout               = 60
  enable_deletion_protection = var.deletion_protection

  tags = { Name = var.project }
}

resource "aws_lb_target_group" "host" {
  name        = "${var.project}-host"
  vpc_id      = aws_vpc.this.id
  port        = 80
  protocol    = "HTTP"
  target_type = "instance"

  deregistration_delay = 30

  # Liveness only (docs/architecture.md §4.2): a host whose php-fpm workers are all stuck stops answering it, which is
  # what §22 A-3 wants noticed. Readiness is not a load balancer concern.
  health_check {
    path                = "/api/health/live"
    matcher             = "200"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  tags = { Name = "${var.project}-host" }
}

resource "aws_lb_target_group_attachment" "host" {
  target_group_arn = aws_lb_target_group.host.arn
  target_id        = aws_instance.host.id
  port             = 80
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      protocol    = "HTTPS"
      port        = "443"
      status_code = "HTTP_301"
    }
  }

  tags = { Name = "${var.project}-http" }
}

resource "aws_lb_listener" "https" {
  count = var.enable_https ? 1 : 0

  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate_validation.this[0].certificate_arn

  default_action {
    type = "fixed-response"

    fixed_response {
      content_type = "text/plain"
      message_body = "Misdirected Request"
      status_code  = "421"
    }
  }

  tags = { Name = "${var.project}-https" }
}

resource "aws_lb_listener_rule" "public_host" {
  count = var.enable_https ? 1 : 0

  listener_arn = aws_lb_listener.https[0].arn
  priority     = 10

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.host.arn
  }

  condition {
    host_header {
      values = [var.public_host]
    }
  }

  tags = { Name = "${var.project}-public-host" }
}
