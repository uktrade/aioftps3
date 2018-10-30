data "aws_route53_zone" "main" {
  name = "${var.route_53_zone}"
}

resource "aws_route53_record" "ftps3_external" {
  zone_id = "${data.aws_route53_zone.main.zone_id}"
  name    = "${var.app_external_host}"
  type    = "A"

  alias {
    name                   = "${aws_lb.app_external.dns_name}"
    zone_id                = "${aws_lb.app_external.zone_id}"
    evaluate_target_health = false
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "ftps3_internal" {
  zone_id = "${data.aws_route53_zone.main.zone_id}"
  name    = "${var.app_internal_host}"
  type    = "A"

  alias {
    name                   = "${aws_lb.app_internal.dns_name}"
    zone_id                = "${aws_lb.app_internal.zone_id}"
    evaluate_target_health = false
  }

  lifecycle {
    create_before_destroy = true
  }
}
