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
