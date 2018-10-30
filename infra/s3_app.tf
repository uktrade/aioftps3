resource "aws_s3_bucket" "app" {
  bucket = "${var.app_bucket}"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
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

resource "aws_iam_user" "app_s3" {
  name = "ftps3-app-s3"
}

resource "aws_iam_access_key" "app_s3" {
  user = "${aws_iam_user.app_s3.name}"
}

data "aws_iam_policy_document" "app_s3" {
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
