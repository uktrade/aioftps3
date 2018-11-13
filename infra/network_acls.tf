resource "aws_network_acl" "nlb_external" {
  vpc_id     = "${data.aws_vpc.main.id}"
  subnet_ids = ["${aws_subnet.public.id}"]

  tags {
    Name = "${var.name}-nlb-external"
  }
}

resource "aws_network_acl_rule" "nlb_external_ingress_command_from_whitelist" {
  count       = "${length(var.ip_whitelist)}"
  rule_number = "${1 + length(var.ip_whitelist) * 0 + count.index}"

  network_acl_id = "${aws_network_acl.nlb_external.id}"
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "${var.ip_whitelist[count.index]}"
  from_port      = "${var.ftp_command_port}"
  to_port        = "${var.ftp_command_port}"
}

resource "aws_network_acl_rule" "nlb_external_ingress_data_from_whitelist" {
  count       = "${length(var.ip_whitelist)}"
  rule_number = "${1 + length(var.ip_whitelist) * 1 + count.index}"

  network_acl_id = "${aws_network_acl.nlb_external.id}"
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "${var.ip_whitelist[count.index]}"
  from_port      = "${var.ftp_data_ports_first}"
  to_port        = "${var.ftp_data_ports_first + var.ftp_data_ports_count}"
}

resource "aws_network_acl_rule" "nlb_external_ingress_ephemeral_from_app" {
  rule_number = "${1 + length(var.ip_whitelist) * 2 + 0}"

  network_acl_id = "${aws_network_acl.nlb_external.id}"
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "${aws_subnet.app.cidr_block}"
  from_port      = "1024"
  to_port        = "65535"
}

resource "aws_network_acl_rule" "nlb_external_egress_ephemeral_to_whitelist" {
  count       = "${length(var.ip_whitelist)}"
  rule_number = "${1 + length(var.ip_whitelist) * 0 + count.index}"

  network_acl_id = "${aws_network_acl.nlb_external.id}"
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "${var.ip_whitelist[count.index]}"
  from_port      = "1024"
  to_port        = "65535"
}

resource "aws_network_acl_rule" "nlb_external_egress_command_to_app" {
  rule_number = "${1 + length(var.ip_whitelist) * 1 + 0}"

  network_acl_id = "${aws_network_acl.nlb_external.id}"
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "${aws_subnet.app.cidr_block}"
  from_port      = "${var.ftp_command_port}"
  to_port        = "${var.ftp_command_port}"
}

resource "aws_network_acl_rule" "nlb_external_egress_data_to_app" {
  rule_number = "${1 + length(var.ip_whitelist) * 1 + 1}"

  network_acl_id = "${aws_network_acl.nlb_external.id}"
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "${aws_subnet.app.cidr_block}"
  from_port      = "${var.ftp_data_ports_first}"
  to_port        = "${var.ftp_data_ports_first + var.ftp_data_ports_count}"
}

resource "aws_network_acl_rule" "nlb_external_egress_healthcheck_to_app" {
  rule_number = "${1 + length(var.ip_whitelist) * 1 + 2}"

  network_acl_id = "${aws_network_acl.nlb_external.id}"
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "${aws_subnet.app.cidr_block}"
  from_port      = "${var.healthcheck_port}"
  to_port        = "${var.healthcheck_port}"
}

resource "aws_network_acl" "nlb_internal" {
  vpc_id     = "${data.aws_vpc.main.id}"
  subnet_ids = ["${aws_subnet.private.id}"]

  tags {
    Name = "${var.name}-nlb-internal"
  }
}

resource "aws_network_acl_rule" "nlb_internal_ingress_command_from_vpc_peer" {
  rule_number = "1"

  network_acl_id = "${aws_network_acl.nlb_internal.id}"
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "${data.aws_vpc_peering_connection.private_subnet.cidr_block}"
  from_port      = "${var.ftp_command_port}"
  to_port        = "${var.ftp_command_port}"
}

resource "aws_network_acl_rule" "nlb_internal_ingress_data_from_vpc_peer" {
  rule_number = "2"

  network_acl_id = "${aws_network_acl.nlb_internal.id}"
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "${data.aws_vpc_peering_connection.private_subnet.cidr_block}"
  from_port      = "${var.ftp_data_ports_first}"
  to_port        = "${var.ftp_data_ports_first + var.ftp_data_ports_count}"
}

resource "aws_network_acl_rule" "nlb_internal_ingress_ephemeral_from_app" {
  rule_number = "3"

  network_acl_id = "${aws_network_acl.nlb_internal.id}"
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "${aws_subnet.app.cidr_block}"
  from_port      = "1024"
  to_port        = "65535"
}

resource "aws_network_acl_rule" "nlb_internal_egress_ephemeral_to_vpc_peer" {
  rule_number = "1"

  network_acl_id = "${aws_network_acl.nlb_internal.id}"
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "${data.aws_vpc_peering_connection.private_subnet.cidr_block}"
  from_port      = "1024"
  to_port        = "65535"
}

resource "aws_network_acl_rule" "nlb_internal_egress_command_to_app" {
  rule_number = "2"

  network_acl_id = "${aws_network_acl.nlb_internal.id}"
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "${aws_subnet.app.cidr_block}"
  from_port      = "${var.ftp_command_port}"
  to_port        = "${var.ftp_command_port}"
}

resource "aws_network_acl_rule" "nlb_internal_egress_data_to_app" {
  rule_number = "3"

  network_acl_id = "${aws_network_acl.nlb_internal.id}"
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "${aws_subnet.app.cidr_block}"
  from_port      = "${var.ftp_data_ports_first}"
  to_port        = "${var.ftp_data_ports_first + var.ftp_data_ports_count}"
}

resource "aws_network_acl_rule" "nlb_internal_egress_healthcheck_to_app" {
  rule_number = "4"

  network_acl_id = "${aws_network_acl.nlb_internal.id}"
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "${aws_subnet.app.cidr_block}"
  from_port      = "${var.healthcheck_port}"
  to_port        = "${var.healthcheck_port}"
}
