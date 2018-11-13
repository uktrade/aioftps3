resource "aws_security_group" "app_service" {
  name        = "${var.name}-app-service"
  description = "${var.name}-app-service"
  vpc_id      = "${data.aws_vpc.main.id}"

  tags {
    Name = "${var.name}-app-service"
  }
}

resource "aws_security_group_rule" "app_service_ingress_command_from_nlbs" {
  description = "ingress-command-from-nlbs"

  security_group_id = "${aws_security_group.app_service.id}"
  cidr_blocks       = [
    "${aws_subnet.public.cidr_block}",
    "${aws_subnet.private.cidr_block}",
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
    "${aws_subnet.private.cidr_block}",
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
    "${aws_subnet.private.cidr_block}",
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
