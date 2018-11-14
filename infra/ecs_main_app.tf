
resource "aws_ecs_service" "app" {
  name            = "${var.name}-app"
  cluster         = "${aws_ecs_cluster.main.id}"
  task_definition = "${aws_ecs_task_definition.app.arn}"
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets         = ["${aws_subnet.app.id}"]
    assign_public_ip = true
    security_groups = ["${aws_security_group.app_service.id}"]
  }
}

resource "aws_ecs_task_definition" "app" {
  family                   = "${var.name}-app"
  container_definitions    = "${data.template_file.app_container_definitions.rendered}"
  execution_role_arn       = "${aws_iam_role.app_task_execution.arn}"
  task_role_arn            = "${aws_iam_role.app_task.arn}"
  network_mode             = "awsvpc"
  cpu                      = "${local.app_container_cpu}"
  memory                   = "${local.app_container_memory}"
  requires_compatibilities = ["FARGATE"]
}

resource "aws_iam_role" "app_task_execution" {
  name               = "${var.name}-app-task-execution"
  path               = "/"
  assume_role_policy = "${data.aws_iam_policy_document.app_task_execution_assume_role.json}"
}

data "aws_iam_policy_document" "app_task_execution_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "app_task_execution" {
  role       = "${aws_iam_role.app_task_execution.name}"
  policy_arn = "${aws_iam_policy.app_task_execution.arn}"
}

resource "aws_iam_policy" "app_task_execution" {
  name        = "${var.name}-app-task-execution"
  path        = "/"
  policy       = "${data.aws_iam_policy_document.app_task_execution.json}"
}

data "aws_iam_policy_document" "app_task_execution" {
  statement {
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = [
      "${aws_cloudwatch_log_group.aws_ecs_task_definition_app.arn}",
    ]
  }
}

resource "aws_iam_role" "app_task" {
  name               = "${var.name}-app-task"
  path               = "/"
  assume_role_policy = "${data.aws_iam_policy_document.app_task_assume_role.json}"
}

data "aws_iam_policy_document" "app_task_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "app_task" {
  role       = "${aws_iam_role.app_task.name}"
  policy_arn = "${aws_iam_policy.app_task.arn}"
}

resource "aws_iam_policy" "app_task" {
  name        = "${var.name}-app-task"
  path        = "/"
  policy       = "${data.aws_iam_policy_document.app_task.json}"
}

data "aws_iam_policy_document" "app_task" {
  statement {
    actions = [
      "s3:ListBucket",
    ]

    resources = [
      "${aws_s3_bucket.app.arn}",
    ]
  }

  statement {
    actions = [
        "s3:PutObject",
        "s3:GetObject",
        "s3:DeleteObject"
    ]

    resources = [
      "${aws_s3_bucket.app.arn}/*",
    ]
  }
}

data "template_file" "app_container_definitions" {
  template = "${file("${path.module}/ecs_main_app_container_definitions.json_template")}"

  vars {
    container_image  = "${var.app_container_image}"
    container_name   = "${local.app_container_name}"
    container_cpu    = "${local.app_container_cpu}"
    container_memory = "${local.app_container_memory}"
    container_ports  = "{\"containerPort\":${var.healthcheck_port}},{\"containerPort\":${var.ftp_command_port}},${join(",", formatlist("{\"containerPort\":%s}", aws_lb_listener.app_public_data.*.port))}"

    log_group  = "${aws_cloudwatch_log_group.aws_ecs_task_definition_app.name}"
    log_region = "${data.aws_region.aws_region.name}"

    aws_s3_bucket_host    = "s3-${aws_s3_bucket.app.region}.amazonaws.com"
    aws_s3_bucket_name    = "${aws_s3_bucket.app.id}"
    aws_s3_bucket_region  = "${aws_s3_bucket.app.region}"

    healthcheck_ftp_user            = "${local.healthcheck_ftp_user}"
    healthcheck_ftp_password_hashed = "${var.healthcheck_ftp_password_hashed}"
    healthcheck_ftp_password_salt   = "${var.healthcheck_ftp_password_salt}"

    ftp_users              = "${join(",", data.template_file.ftp_users_json.*.rendered)}"
    ftp_command_port       = "${var.ftp_command_port}"
    ftp_data_ports_first   = "${var.ftp_data_ports_first}"
    ftp_data_ports_count   = "${var.ftp_data_ports_count}"

    ftp_data_cidr_to_domains__1__cidr = "${aws_subnet.public.cidr_block}"
    ftp_data_cidr_to_domains__1__domain = "${aws_lb.app_public.dns_name}"
    ftp_data_cidr_to_domains__2__cidr = "${aws_subnet.private.cidr_block}"
    ftp_data_cidr_to_domains__2__domain = "${aws_lb.app_private.dns_name}"

    healthcheck_port = "${var.healthcheck_port}"
  }
}

data "template_file" "ftp_users_json" {
  count    = "${length(var.ftp_users)}"
  template = "${file("${path.module}/ecs_main_app_ftp_user.json_template")}"

  vars {
    index           = "${count.index + 1}"
    login           = "${lookup(var.ftp_users[count.index], "login")}"
    password_hashed = "${lookup(var.ftp_users[count.index], "password_hashed")}"
    password_salt   = "${lookup(var.ftp_users[count.index], "password_salt")}"
  }
}

resource "aws_cloudwatch_log_group" "aws_ecs_task_definition_app" {
  name              = "${var.name}-app"
  retention_in_days = "3653"
}
