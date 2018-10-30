resource "aws_lb" "app_external" {
  name               = "ftps3-app-external"
  internal           = false
  load_balancer_type = "network"
  subnets            = ["${aws_subnet.public.id}"]
}

resource "aws_lb_listener" "app_external_command" {
  load_balancer_arn = "${aws_lb.app_external.arn}"
  port              = "${var.ftp_command_port}"
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = "${aws_lb_target_group.app_external_command.arn}"
  }
}

resource "aws_lb_target_group" "app_external_command" {
  name_prefix = "ec${var.ftp_command_port}"
  port        = "${var.ftp_command_port}"
  protocol    = "TCP"
  vpc_id      = "${data.aws_vpc.main.id}"
  target_type = "ip"

  health_check {
    interval = 10
    port = "${var.ftp_command_port}"
    protocol = "TCP"
    healthy_threshold = 2
    unhealthy_threshold = 2
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_lb_listener" "app_external_data" {
  count             = "${var.ftp_data_ports_count}"
  load_balancer_arn = "${aws_lb.app_external.arn}"
  port              = "${lookup(data.null_data_source.ftp_data_ports.*.outputs[count.index], "port")}"
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = "${aws_lb_target_group.app_external_data.*.arn[count.index]}"
  }
}

resource "aws_lb_target_group" "app_external_data" {
  count       = "${var.ftp_data_ports_count}"
  name_prefix = "ed${lookup(data.null_data_source.ftp_data_ports.*.outputs[count.index], "port")}"
  port        = "${lookup(data.null_data_source.ftp_data_ports.*.outputs[count.index], "port")}"
  protocol    = "TCP"
  vpc_id      = "${data.aws_vpc.main.id}"
  target_type = "ip"

  health_check {
    interval = 10
    port = "${var.ftp_command_port}"
    protocol = "TCP"
    healthy_threshold = 2
    unhealthy_threshold = 2
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_lb_target_group_attachment" "app_external_command" {
  count            = "${var.private_subnet_hosts_count}"
  target_group_arn = "${aws_lb_target_group.app_external_command.arn}"
  port             = "${var.ftp_command_port}"
  target_id        = "${lookup(data.null_data_source.app_ips.*.outputs[count.index], "ip")}"
}

resource "aws_lb_target_group_attachment" "app_external_data" {
  count            = "${var.private_subnet_hosts_count * var.ftp_data_ports_count}"
  target_group_arn = "${aws_lb_target_group.app_external_data.*.arn[count.index % var.ftp_data_ports_count]}"
  port             = "${lookup(data.null_data_source.ftp_data_ports.*.outputs[count.index % var.ftp_data_ports_count], "port")}"
  target_id        = "${lookup(data.null_data_source.app_ips.*.outputs[count.index % var.private_subnet_hosts_count], "ip")}"
}
