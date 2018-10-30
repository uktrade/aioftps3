resource "aws_security_group" "app_service" {
  name        = "ftps3-app-service"
  description = "ftps3-app-service"
  vpc_id      = "${data.aws_vpc.main.id}"

  tags {
    Name = "ftps3-app-service"
  }
}

resource "aws_security_group_rule" "app_service_ingress_command_from_whitelist" {
  description = "ingress-command-from-whitelist"

  security_group_id = "${aws_security_group.app_service.id}"
  cidr_blocks       = ["${var.ip_whitelist}"]

  type      = "ingress"
  from_port = "${var.ftp_command_port}"
  to_port   = "${var.ftp_command_port}"
  protocol  = "tcp"
}

resource "aws_security_group_rule" "app_service_ingress_data_from_whitelist" {
  description = "ingress-data-from-whitelist"

  security_group_id = "${aws_security_group.app_service.id}"
  cidr_blocks       = ["${var.ip_whitelist}"]

  type      = "ingress"
  from_port = "${var.ftp_data_ports_first}"
  to_port   = "${var.ftp_data_ports_first + var.ftp_data_ports_count}"
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
