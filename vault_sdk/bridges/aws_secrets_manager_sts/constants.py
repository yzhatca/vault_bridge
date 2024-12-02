# need to change the below information using service account info
# AWS_ACCESS_KEY_ID = "access_key_id"
# AWS_SECRET_ACCESS_KEY = "secret_access_key"

# Vault service default configuration
DEFAULT_VAULT_URL = "https://default-secretsmanager.aws.com"
DEFAULT_ROLE_ARN = "arn:aws:iam::123456789012:role/DefaultRole"
DEFAULT_SESSION_NAME = "default-session"
DEFAULT_REGION = "us-east-1"  # 默认 AWS 区域



SECRET_ID = "secret_id"
ERROR_SECRET_ID_NOT_FOUND = "Secret id is not found from secret_reference_metadata"
INVALID_JSON_FORMAT_ERROR = "Invalid JSON format for secret_value"
INVALID_VAULT_URL_ERROR = "Invalid Vault URL. Missing {} in the URL"