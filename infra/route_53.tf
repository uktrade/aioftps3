data "aws_route53_zone" "main" {
  name = "${var.route_53_zone}"
}

resource "aws_route53_record" "ftps3_public" {
  zone_id = "${data.aws_route53_zone.main.zone_id}"
  name    = "${var.app_external_host}"
  type    = "A"

  alias {
    name                   = "${aws_lb.app_public.dns_name}"
    zone_id                = "${aws_lb.app_public.zone_id}"
    evaluate_target_health = false
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "ftps3_private" {
  zone_id = "${data.aws_route53_zone.main.zone_id}"
  name    = "${var.app_internal_host}"
  type    = "A"

  alias {
    name                   = "${aws_lb.app_private.dns_name}"
    zone_id                = "${aws_lb.app_private.zone_id}"
    evaluate_target_health = false
  }

  lifecycle {
    create_before_destroy = true
  }
}
