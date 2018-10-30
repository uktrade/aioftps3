data "aws_vpc" "main" {
  id = "${var.vpc_id}"
}

data "aws_route_table" "main" {
  route_table_id = "${var.route_table_id}"
}

resource "aws_subnet" "main" {
  vpc_id     = "${data.aws_vpc.main.id}"
  cidr_block = "${var.subnet_cidr}"

  availability_zone = "${var.availability_zone}"

  tags {
    Name = "ftps3-${var.availability_zone}"
  }
}

resource "aws_route_table_association" "jupyterhub_public" {
  subnet_id      = "${aws_subnet.main.id}"
  route_table_id = "${data.aws_route_table.main.route_table_id}"
}
