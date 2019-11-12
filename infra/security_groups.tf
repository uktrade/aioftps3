resource "aws_security_group" "app_service" {
  name        = "${var.name}-app-service"
  description = "${var.name}-app-service"
  vpc_id      = "${data.aws_vpc.main.id}"

  tags {
    Name = "${var.name}-app-service"
  }
}

# resource "aws_security_group_rule" "app_service_ingress_everything_from_everywhere" {
#   description = "ingress-everything-from-everywhere"

#   security_group_id = "${aws_security_group.app_service.id}"
#   cidr_blocks       = [
#     "0.0.0.0/0",
#   ]

#   type      = "ingress"
#   from_port = "0"
#   to_port   = "65535"
#   protocol  = "tcp"
# }

resource "aws_security_group_rule" "app_service_ingress_command_from_nlbs" {
  description = "ingress-command-from-nlbs"

  security_group_id = "${aws_security_group.app_service.id}"
  cidr_blocks       = [
    "${aws_subnet.public.cidr_block}",
  ]

  type      = "ingress"
  from_port = "${var.ftp_command_port}"
  to_port   = "${var.ftp_command_port}"
  protocol  = "tcp"
}

resource "aws_security_group_rule" "app_service_ingress_data_from_nlbs" {
  description = "ingress-command-from-nlbs"

  security_group_id = "${aws_security_group.app_service.id}"
  cidr_blocks       = [
    "${aws_subnet.public.cidr_block}",
  ]

  type      = "ingress"
  from_port = "${var.ftp_data_ports_first}"
  to_port   = "${var.ftp_data_ports_first + var.ftp_data_ports_count}"
  protocol  = "tcp"
}

resource "aws_security_group_rule" "app_service_ingress_healthcheck_from_nlbs" {
  description = "ingress-healthcheck-from-nlbs"

  security_group_id = "${aws_security_group.app_service.id}"
  cidr_blocks       = [
    "${aws_subnet.public.cidr_block}",
  ]

  type      = "ingress"
  from_port = "${var.healthcheck_port}"
  to_port   = "${var.healthcheck_port}"
  protocol  = "tcp"
}

resource "aws_security_group_rule" "app_service_egress_https_to_everywhere" {
  description = "egress-https-to-everywhere"

  security_group_id = "${aws_security_group.app_service.id}"
  cidr_blocks       = ["0.0.0.0/0"]

  type      = "egress"
  from_port = "443"
  to_port   = "443"
  protocol  = "tcp"
}

resource "aws_security_group" "healthcheck_alb" {
  name        = "${var.name}-healthcheck-alb"
  description = "${var.name}-healthcheck-alb"
  vpc_id      = "${data.aws_vpc.main.id}"

  tags {
    Name = "${var.name}-healthcheck"
  }
}

resource "aws_security_group_rule" "healthcheck_alb_ingress_https_from_everywhere" {
  description = "ingress-https-from-everywhere"

  security_group_id = "${aws_security_group.healthcheck_alb.id}"
  cidr_blocks       = ["0.0.0.0/0"]

  type      = "ingress"
  from_port = "443"
  to_port   = "443"
  protocol  = "tcp"
}

resource "aws_security_group_rule" "healthcheck_alb_egress_http_to_healthcheck_service" {
  description = "egress-http-to-healthcheck-service"

  security_group_id        = "${aws_security_group.healthcheck_alb.id}"
  source_security_group_id = "${aws_security_group.healthcheck_service.id}"

  type      = "egress"
  from_port = "${local.healthcheck_container_port}"
  to_port   = "${local.healthcheck_container_port}"
  protocol  = "tcp"
}

resource "aws_security_group" "healthcheck_service" {
  name        = "${var.name}-healthcheck-service"
  description = "${var.name}-healthcheck-service"
  vpc_id      = "${data.aws_vpc.main.id}"

  tags {
    Name = "${var.name}-healthcheck"
  }
}

resource "aws_security_group_rule" "healthcheck_service_ingress_http_from_alb" {
  description = "ingress-http-from-alb"

  security_group_id        = "${aws_security_group.healthcheck_service.id}"
  source_security_group_id = "${aws_security_group.healthcheck_alb.id}"

  type      = "ingress"
  from_port = "${local.healthcheck_container_port}"
  to_port   = "${local.healthcheck_container_port}"
  protocol  = "tcp"
}

resource "aws_security_group_rule" "healthcheck_egress_https_to_everywhere" {
  description = "egress-https-to-everywhere"

  security_group_id = "${aws_security_group.healthcheck_service.id}"
  cidr_blocks       = ["0.0.0.0/0"]

  type      = "egress"
  from_port = "443"
  to_port   = "443"
  protocol  = "tcp"
}

resource "aws_security_group_rule" "healthcheck_egress_command_to_app_public" {
  description = "egress-command-to-app-public"

  security_group_id = "${aws_security_group.healthcheck_service.id}"
  cidr_blocks       = ["${data.aws_eip.app_public.public_ip}/32"]

  type      = "egress"
  from_port = "${var.ftp_command_port}"
  to_port   = "${var.ftp_command_port}"
  protocol  = "tcp"
}

resource "aws_security_group_rule" "healthcheck_egress_data_to_app_public" {
  description = "egress-data-to-app-public"

  security_group_id = "${aws_security_group.healthcheck_service.id}"
  cidr_blocks       = ["${data.aws_eip.app_public.public_ip}/32"]

  type      = "egress"
  from_port = "${var.ftp_data_ports_first}"
  to_port   = "${var.ftp_data_ports_first + var.ftp_data_ports_count}"
  protocol  = "tcp"
}
