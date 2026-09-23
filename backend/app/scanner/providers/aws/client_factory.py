"""
AWS Client Factory with strict credential protection and credential provider chain resolution.
"""

import logging
from typing import Optional, Dict, Any
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, BotoCoreError, NoCredentialsError

from app.core.config import settings

logger = logging.getLogger("cspm.aws.factory")


def mask_credential(val: Optional[str]) -> str:
    """Masks sensitive credential strings for safe logging."""
    if not val:
        return "NONE"
    if len(val) <= 8:
        return "****"
    return f"{val[:4]}****{val[-4:]}"


class AWSClientFactory:
    """
    Factory creating configured boto3 service clients.
    Resolves credentials via standard AWS credential provider chain:
    1. Explicit environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    2. Named profile (AWS_PROFILE)
    3. IAM instance profile / ECS task role
    4. Optional AssumeRole via STS
    """

    def __init__(
        self,
        region_name: Optional[str] = None,
        profile_name: Optional[str] = None,
        role_arn: Optional[str] = None,
        external_id: Optional[str] = None,
        target_account_id: Optional[str] = None,
    ):
        self.region_name = region_name or settings.AWS_DEFAULT_REGION or "us-east-1"
        self.profile_name = profile_name
        self.role_arn = role_arn or settings.AWS_ASSUME_ROLE_ARN
        self.external_id = external_id
        self.target_account_id = target_account_id

        # Configure standard retry and timeout posture
        self._boto_config = Config(
            region_name=self.region_name,
            retries={"max_attempts": 3, "mode": "standard"},
            connect_timeout=10,
            read_timeout=30,
        )
        self._session: Optional[boto3.Session] = None
        self._initialize_session()

    def _initialize_session(self) -> None:
        """Initializes the base boto3.Session safely."""
        session_kwargs: Dict[str, Any] = {"region_name": self.region_name}

        if self.profile_name:
            session_kwargs["profile_name"] = self.profile_name
        elif settings.AWS_ACCESS_KEY_ID and settings.AWS_SECRET_ACCESS_KEY:
            session_kwargs["aws_access_key_id"] = settings.AWS_ACCESS_KEY_ID
            session_kwargs["aws_secret_access_key"] = settings.AWS_SECRET_ACCESS_KEY
            if settings.AWS_SESSION_TOKEN:
                session_kwargs["aws_session_token"] = settings.AWS_SESSION_TOKEN

        self._session = boto3.Session(**session_kwargs)

        # Handle AssumeRole if configured
        if self.role_arn:
            logger.info(f"Assuming role: {self.role_arn}")
            sts_client = self._session.client("sts", config=self._boto_config)
            session_name = f"CSPM-{self.target_account_id or 'Scanner'}"[:64]
            assume_kwargs: Dict[str, Any] = {
                "RoleArn": self.role_arn,
                "RoleSessionName": session_name,
                "DurationSeconds": 3600,
            }
            if self.external_id:
                assume_kwargs["ExternalId"] = self.external_id

            assumed = sts_client.assume_role(**assume_kwargs)
            creds = assumed["Credentials"]
            self._session = boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=self.region_name,
            )
            logger.info(f"Successfully assumed role {self.role_arn}")

    def get_client(self, service_name: str, region_name: Optional[str] = None) -> Any:
        """Creates and returns a client for the specified AWS service."""
        target_region = region_name or self.region_name
        config = self._boto_config
        if target_region != self.region_name:
            config = Config(
                region_name=target_region,
                retries={"max_attempts": 3, "mode": "standard"},
                connect_timeout=10,
                read_timeout=30,
            )

        return self._session.client(service_name, config=config)

    def test_sts_connection(self) -> Dict[str, Any]:
        """
        Validates credentials and connectivity via sts:GetCallerIdentity.
        Returns account info or raises an exception.
        If target_account_id is configured and is numeric, verifies that
        the STS identity matches the expected target account.
        """
        sts = self.get_client("sts")
        identity = sts.get_caller_identity()
        caller_account = identity.get("Account")

        if (
            self.target_account_id
            and self.target_account_id.isdigit()
            and caller_account
            and self.target_account_id != caller_account
        ):
            raise ValueError(
                f"Account ID mismatch: authenticated as AWS Account '{caller_account}', "
                f"but target account is configured as '{self.target_account_id}'."
            )

        return {
            "account_id": caller_account,
            "arn": identity.get("Arn"),
            "user_id": identity.get("UserId"),
        }
