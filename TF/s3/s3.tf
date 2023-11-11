variable "CODEPIPELINE" {}

resource "random_string" "random" {
  length    = 8
  min_lower = 8
  special   = false

}

resource "aws_s3_bucket" "codepipeline-bucket" {
  bucket = lower(join("", [var.CODEPIPELINE["S3"], "-", random_string.random.result]))
}


resource "aws_s3_bucket_versioning" "bucket-versioning" {
  bucket = aws_s3_bucket.codepipeline-bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

output "S3_INFO" {
  value = aws_s3_bucket.codepipeline-bucket
}
