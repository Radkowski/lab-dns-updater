

module "S3" {
  source       = "./s3"
  CODEPIPELINE = local.CODEPIPELINE
}

module "CICD" {
  source           = "./cicd"
  depends_on       = [module.S3]
  DEPLOYMENTPREFIX = local.DEPLOYMENTPREFIX
  S3_INFO          = module.S3.S3_INFO
  AUTHTAGS         = local.AUTHTAGS
}


output "S3_INFO" {
  value = module.S3.S3_INFO.bucket
}