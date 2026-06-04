# pass

resource "aws_lambda_function" "pass" {
  function_name = "test-env"
  role          = ""
  runtime       = "python3.9"

  environment {
    variables = {
      AWS_DEFAULT_REGION = "us-west-2"
    }
  }
}

resource "aws_lambda_function" "no_env" {
  function_name = "test-env"
  role          = ""
  runtime       = "python3.9"
}

# pass - non-secret config values that are 40/48 chars long (issue #7542)

resource "aws_lambda_function" "pass_nonsecret_long_values" {
  function_name = "test-env"
  role          = ""
  runtime       = "python3.9"

  environment {
    variables = {
      METRIC_NAMESPACE = "mdp/feature-logging/FdaCompositePipeline"
      FDA_DOWNLOAD_URL = "https://www.fda.gov/media/76860/download"
      S3_BUCKET        = "mdp-test-new-destroy-147997161038-uploads-bucket"
      TABLE_NAME       = "myappprodtablename0123456789abcdefghijkl"
    }
  }
}

# fail

resource "aws_lambda_function" "fail" {
  function_name = "stest-env"
  role          = ""
  runtime       = "python3.9"

  environment {
    variables = {
      AWS_ACCESS_KEY_ID     = "AKIAIOSFODNN7EXAMPLE",  # checkov:skip=CKV_SECRET_2 test secret
      AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",  # checkov:skip=CKV_SECRET_2 test secret
      AWS_DEFAULT_REGION    = "us-west-2"
    }
  }
}
