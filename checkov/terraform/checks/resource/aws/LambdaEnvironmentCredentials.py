import re
from typing import Any, Dict, List

from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.util.secrets import string_has_secrets, AWS, GENERAL
from checkov.common.util.type_forcers import force_list

# A bare run of exactly 40 base64 characters matches the generic "AWS secret access key"
# regex in checkov.common.util.secrets. Lambda environment values such as resource names,
# bucket names and URL fragments that happen to be 40 characters long therefore get flagged
# even though they hold no secret (see GitHub issue #7542). A real AWS secret access key is
# base64 of 30 random bytes, so in practice it always mixes upper-case, lower-case and digit
# characters. A coincidental 40-character resource name almost never does (it is typically
# lower-case plus digits). We use that structural property to drop the bare-40-run match for
# values that cannot plausibly be an AWS secret access key, while leaving every other secret
# pattern (AKIA... access key IDs, keyword-anchored secret keys, PEM blocks, etc.) untouched.
_BARE_40_RUN = re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])")


def _is_plausible_aws_secret_key(token: str) -> bool:
    return (
        any(c.islower() for c in token)
        and any(c.isupper() for c in token)
        and any(c.isdigit() for c in token)
    )


def _value_has_secret(value: str) -> bool:
    if not string_has_secrets(value, AWS, GENERAL):
        return False

    # If the only reason the value matched is a bare 40-character run that does not look like a
    # real AWS secret access key, treat it as a non-secret. We strip every such low-confidence
    # run and re-check; if anything still matches, the value is a genuine secret.
    stripped = _BARE_40_RUN.sub(
        lambda m: "" if not _is_plausible_aws_secret_key(m.group()) else m.group(),
        value,
    )
    if stripped == value:
        # No bare-40-run was dropped, so the original match stands.
        return True
    return string_has_secrets(stripped, AWS, GENERAL)


class LambdaEnvironmentCredentials(BaseResourceCheck):
    def __init__(self) -> None:
        name = "Ensure no hard-coded secrets exist in lambda environment"
        id = "CKV_AWS_45"
        supported_resources = ["aws_lambda_function"]
        categories = [CheckCategories.SECRETS]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf: Dict[str, List[Any]]) -> CheckResult:
        environment = conf.get("environment", [])
        if environment and isinstance(environment[0], dict):
            self.evaluated_keys = ["environment"]

            variables = force_list(environment[0].get("variables", []))
            if variables and isinstance(variables[0], dict):
                self.evaluated_keys = ["environment/[0]/variables"]

                violated_envs = set()
                for key, values in variables[0].items():
                    # variables can be a string, which in this case it points to a variable
                    for idx, value in enumerate([v for v in force_list(values) if isinstance(v, str)]):
                        if _value_has_secret(value):
                            conf[f'{self.id}_secret_{idx}'] = value
                            violated_envs.add(key)

                if violated_envs:
                    self.evaluated_keys = [f"environment/[0]/variables/[0]/{env_key}" for env_key in violated_envs]

                    return CheckResult.FAILED
        return CheckResult.PASSED


check = LambdaEnvironmentCredentials()
