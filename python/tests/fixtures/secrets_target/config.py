# Example config — intentionally contains secrets for test purposes

import os

# AWS credentials hardcoded (bad practice — for testing only)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "aws_secret_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Generic API key
api_key = "abc123-super-secret-api-key-value-here"
API_TOKEN = "some_api_token = 'sk-live-abcdef1234567890abcdef'"

# Hardcoded password
password = "mysupersecretpassword123"
db_password = "hunter2"

# JWT token (fake, for testing)
JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# Database connection strings
DB_URL = "postgresql://admin:secretpassword@db.example.com:5432/mydb"
MONGO_URI = "mongodb://user:pass@cluster.example.com/mydb"

# This one should NOT match (env var reference is fine)
SAFE_KEY = os.environ.get("API_KEY")
