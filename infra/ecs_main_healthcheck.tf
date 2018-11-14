resource "aws_ecs_service" "healthcheck" {
  name            = "${var.name}-healthcheck"
  cluster         = "${aws_ecs_cluster.main.id}"
  task_definition = "${aws_ecs_task_definition.healthcheck.arn}"
  desired_count   = 1
  launch_type     = "FARGATE"

  load_balancer {
    target_group_arn = "${aws_alb_target_group.healthcheck.arn}"
    container_port   = "${local.healthcheck_container_port}"
    container_name   = "${local.healthcheck_container_name}"
  }

  network_configuration {
    subnets          = ["${aws_subnet.healthcheck_private.id}"]
    assign_public_ip = false
    security_groups  = ["${aws_security_group.healthcheck_service.id}"]
  }
}

resource "aws_ecs_task_definition" "healthcheck" {
  family                   = "${var.name}-healthcheck"
  container_definitions    = "${data.template_file.healthcheck_container_definitions.rendered}"
  execution_role_arn       = "${aws_iam_role.healthcheck_task_execution.arn}"
  task_role_arn            = "${aws_iam_role.healthcheck_task.arn}"
  network_mode             = "awsvpc"

  cpu                      = "${local.healthcheck_container_cpu}"
  memory                   = "${local.healthcheck_container_memory}"
  requires_compatibilities = ["FARGATE"]
}

resource "aws_iam_role" "healthcheck_task_execution" {
  name               = "${var.name}-healthcheck-task-execution"
  path               = "/"
  assume_role_policy = "${data.aws_iam_policy_document.healthcheck_task_execution_assume_role.json}"
}

data "aws_iam_policy_document" "healthcheck_task_execution_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "healthcheck_task_execution" {
  role       = "${aws_iam_role.healthcheck_task_execution.name}"
  policy_arn = "${aws_iam_policy.healthcheck_task_execution.arn}"
}

resource "aws_iam_policy" "healthcheck_task_execution" {
  name        = "${var.name}-healthcheck-task-execution"
  path        = "/"
  policy       = "${data.aws_iam_policy_document.healthcheck_task_execution.json}"
}

data "aws_iam_policy_document" "healthcheck_task_execution" {
  statement {
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = [
      "${aws_cloudwatch_log_group.aws_ecs_task_definition_healthcheck.arn}",
    ]
  }
}

resource "aws_iam_role" "healthcheck_task" {
  name               = "${var.name}-healthcheck-task"
  path               = "/"
  assume_role_policy = "${data.aws_iam_policy_document.healthcheck_task_assume_role.json}"
}

data "aws_iam_policy_document" "healthcheck_task_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

data "template_file" "healthcheck_container_definitions" {
  template = "${file("${path.module}/ecs_main_healthcheck_container_definitions.json_template")}"

  vars {
    container_image  = "${var.healthcheck_container_image}"
    container_name   = "${local.healthcheck_container_name}"
    container_cpu    = "${local.healthcheck_container_cpu}"
    container_memory = "${local.healthcheck_container_memory}"
    container_port   = "${local.healthcheck_container_port}"

    log_group  = "${aws_cloudwatch_log_group.aws_ecs_task_definition_healthcheck.name}"
    log_region = "${data.aws_region.aws_region.name}"

    ftp_host         = "${aws_route53_record.ftps3_public.name}"
    ftp_command_port = "${var.ftp_command_port}"
    ftp_user         = "${local.healthcheck_ftp_user}"
    ftp_password     = "${var.healthcheck_ftp_password}"
  }
}

resource "aws_cloudwatch_log_group" "aws_ecs_task_definition_healthcheck" {
  name              = "${var.name}-healthcheck"
  retention_in_days = "3653"
}

resource "aws_alb" "healthcheck" {
  name            = "${var.name}-healthcheck"
  subnets         = [
    "${aws_subnet.healthcheck_public_a.id}",
    "${aws_subnet.healthcheck_public_b.id}",
  ]
  security_groups = ["${aws_security_group.healthcheck_alb.id}"]
}

resource "aws_alb_listener" "healthcheck" {
  load_balancer_arn = "${aws_alb.healthcheck.arn}"
  port              = "443"
  protocol          = "HTTPS"

  default_action {
    target_group_arn = "${aws_alb_target_group.healthcheck.arn}"
    type             = "forward"
  }

  ssl_policy      = "ELBSecurityPolicy-TLS-1-2-2017-01"
  certificate_arn = "${aws_acm_certificate_validation.healthcheck.certificate_arn}"
}

resource "aws_alb_target_group" "healthcheck" {
  name_prefix = "hc-"
  port        = "${local.healthcheck_container_port}"
  protocol    = "HTTP"
  vpc_id      = "${data.aws_vpc.main.id}"
  target_type = "ip"

  health_check {
    protocol = "HTTP"
    port = "${local.healthcheck_container_port}"
    path = "/alb_healthcheck"
    healthy_threshold = 3
    unhealthy_threshold = 3
  }

  lifecycle {
    create_before_destroy = true
  }
}
