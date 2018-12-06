resource "aws_s3_bucket" "app" {
  bucket = "${var.app_bucket}"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  logging {
    target_bucket = "${aws_s3_bucket.app_access_log.id}"
    target_prefix = "${var.app_bucket}/"
  }

  lifecycle_rule {
    enabled = true
    abort_incomplete_multipart_upload_days = 2
  }
}

resource "aws_s3_bucket_policy" "app" {
  bucket = "${aws_s3_bucket.app.id}"
  policy = "${data.aws_iam_policy_document.app.json}"
}

data "aws_iam_policy_document" "app" {
  statement {
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions = [
      "s3:*",
    ]
    resources = [
      "arn:aws:s3:::${aws_s3_bucket.app.id}",
      "arn:aws:s3:::${aws_s3_bucket.app.id}/*",
    ]
    condition {
      test = "Bool"
      variable = "aws:SecureTransport"
      values = [
        "false"
      ]
    }
  }
}

resource "aws_s3_bucket" "app_acme" {
  bucket = "${var.app_bucket}-acme"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  logging {
    target_bucket = "${aws_s3_bucket.app_access_log.id}"
    target_prefix = "${var.app_bucket}-acme/"
  }

  lifecycle_rule {
    enabled = true
    abort_incomplete_multipart_upload_days = 2
  }
}

resource "aws_s3_bucket_object" "acme_account_key" {
  bucket = "${aws_s3_bucket.app_acme.bucket}"
  key    = "account.key"
  source = "account.key"
  etag   = "${md5(file("account.key"))}"
}

resource "aws_s3_bucket_object" "acme_private_ssl_key" {
  bucket = "${aws_s3_bucket.app_acme.bucket}"
  key    = "${aws_route53_record.ftps3_private.name}.key"
  source = "${aws_route53_record.ftps3_private.name}.key"
  etag   = "${md5(file("${aws_route53_record.ftps3_private.name}.key"))}"
}

resource "aws_s3_bucket_object" "acme_private_ssl_csr" {
  bucket = "${aws_s3_bucket.app_acme.bucket}"
  key    = "${aws_route53_record.ftps3_private.name}.csr"
  source = "${aws_route53_record.ftps3_private.name}.csr"
  etag   = "${md5(file("${aws_route53_record.ftps3_private.name}.csr"))}"
}

resource "aws_s3_bucket_object" "acme_public_ssl_key" {
  bucket = "${aws_s3_bucket.app_acme.bucket}"
  key    = "${aws_route53_record.ftps3_public.name}.key"
  source = "${aws_route53_record.ftps3_public.name}.key"
  etag   = "${md5(file("${aws_route53_record.ftps3_public.name}.key"))}"
}

resource "aws_s3_bucket_object" "acme_public_ssl_csr" {
  bucket = "${aws_s3_bucket.app_acme.bucket}"
  key    = "${aws_route53_record.ftps3_public.name}.csr"
  source = "${aws_route53_record.ftps3_public.name}.csr"
  etag   = "${md5(file("${aws_route53_record.ftps3_public.name}.csr"))}"
}

data "aws_iam_policy_document" "app_acme" {
  statement {
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions = [
      "s3:*",
    ]
    resources = [
      "arn:aws:s3:::${aws_s3_bucket.app_acme.id}",
      "arn:aws:s3:::${aws_s3_bucket.app_acme.id}/*",
    ]
    condition {
      test = "Bool"
      variable = "aws:SecureTransport"
      values = [
        "false"
      ]
    }
  }
}

resource "aws_s3_bucket" "app_access_log" {
  bucket = "${var.app_bucket}-access-log"
  acl    = "log-delivery-write"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  lifecycle_rule {
    enabled = true
    abort_incomplete_multipart_upload_days = 2
  }
}

resource "aws_s3_bucket_policy" "app_access_log" {
  bucket = "${aws_s3_bucket.app_access_log.id}"
  policy = "${data.aws_iam_policy_document.app_access_log.json}"
}

data "aws_iam_policy_document" "app_access_log" {
  statement {
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions = [
      "s3:*",
    ]
    resources = [
      "arn:aws:s3:::${aws_s3_bucket.app_access_log.id}",
      "arn:aws:s3:::${aws_s3_bucket.app_access_log.id}/*",
    ]
    condition {
      test = "Bool"
      variable = "aws:SecureTransport"
      values = [
        "false"
      ]
    }
  }
}
