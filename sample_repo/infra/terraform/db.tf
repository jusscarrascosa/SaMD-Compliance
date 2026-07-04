resource "aws_db_instance" "clinical_db" {
  identifier              = "clinical-records"
  engine                  = "postgres"
  storage_encrypted       = true
  kms_key_id              = aws_kms_key.clinical.arn
  backup_retention_period = 7
}

resource "aws_kms_key" "clinical" {
  description             = "KMS key for clinical PHI at rest"
  deletion_window_in_days = 30
}
