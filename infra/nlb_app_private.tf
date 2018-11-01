resource "aws_lb" "app_private" {
  name               = "ftps3-app-private"
  internal           = true
  load_balancer_type = "network"
  subnets            = ["${aws_subnet.private.id}"]
}

resource "aws_lb_listener" "app_private_command" {
  load_balancer_arn = "${aws_lb.app_private.arn}"
  port              = "${var.ftp_command_port}"
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = "${aws_lb_target_group.app_private_command.arn}"
  }
}

resource "aws_lb_target_group" "app_private_command" {
  name_prefix = "ic${var.ftp_command_port}"
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

resource "aws_lb_listener" "app_private_data" {
  count             = "${var.ftp_data_ports_count}"
  load_balancer_arn = "${aws_lb.app_private.arn}"
  port              = "${lookup(data.null_data_source.ftp_data_ports.*.outputs[count.index], "port")}"
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = "${aws_lb_target_group.app_private_data.*.arn[count.index]}"
  }
}

resource "aws_lb_target_group" "app_private_data" {
  count       = "${var.ftp_data_ports_count}"
  name_prefix = "id${lookup(data.null_data_source.ftp_data_ports.*.outputs[count.index], "port")}"
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

resource "aws_lb_target_group_attachment" "app_private_command" {
  count             = "${var.app_subnet_hosts_count}"
  target_group_arn  = "${aws_lb_target_group.app_private_command.arn}"
  port              = "${var.ftp_command_port}"
  target_id         = "${lookup(data.null_data_source.app_ips.*.outputs[count.index], "ip")}"
  availability_zone = "${var.availability_zone}"
}

resource "aws_lb_target_group_attachment" "app_private_data" {
  count             = "${var.app_subnet_hosts_count * var.ftp_data_ports_count}"
  target_group_arn  = "${aws_lb_target_group.app_private_data.*.arn[count.index % var.ftp_data_ports_count]}"
  port              = "${lookup(data.null_data_source.ftp_data_ports.*.outputs[count.index % var.ftp_data_ports_count], "port")}"
  target_id         = "${lookup(data.null_data_source.app_ips.*.outputs[count.index % var.app_subnet_hosts_count], "ip")}"
  availability_zone = "${var.availability_zone}"
}
