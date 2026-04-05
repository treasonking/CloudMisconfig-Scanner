from __future__ import annotations

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError, ProfileNotFound

from scanner.core.models import ScanContext, ScanResult


PUBLIC_GRANTEE_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}


class AWSProvider:
    name = "aws"

    def __init__(self, region_name: str = "ap-northeast-2", profile_name: str | None = "default"):
        self.region_name = region_name
        self.profile_name = profile_name

    def _session(self) -> boto3.Session:
        if self.profile_name:
            return boto3.Session(profile_name=self.profile_name, region_name=self.region_name)
        return boto3.Session(region_name=self.region_name)

    def collect(self) -> ScanResult:
        context = ScanContext(provider=self.name, region=self.region_name, profile=self.profile_name)
        result = ScanResult(context=context)

        try:
            session = self._session()

            sts = session.client("sts")
            identity = sts.get_caller_identity()
            result.data["identity"] = {
                "account": identity["Account"],
                "arn": identity["Arn"],
                "user_id": identity["UserId"],
            }

            s3 = session.client("s3")
            buckets = s3.list_buckets().get("Buckets", [])
            bucket_names = [bucket["Name"] for bucket in buckets]
            result.data["s3_buckets"] = bucket_names
            result.data["s3_bucket_security"] = self._collect_s3_bucket_security(s3, bucket_names)

            iam = session.client("iam")
            users = iam.list_users().get("Users", [])
            user_names = [user["UserName"] for user in users]
            result.data["iam_users"] = user_names
            result.data["iam_user_mfa"] = self._collect_iam_user_mfa(iam, user_names)

        except ProfileNotFound:
            result.errors.append(f"AWS profile '{self.profile_name}' 을 찾을 수 없습니다.")
        except NoCredentialsError:
            result.errors.append("AWS 자격 증명을 찾을 수 없습니다.")
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            message = exc.response.get("Error", {}).get("Message", str(exc))
            result.errors.append(f"{code}: {message}")
        except BotoCoreError as exc:
            result.errors.append(str(exc))
        except Exception as exc:
            result.errors.append(str(exc))

        return result

    def _collect_s3_bucket_security(self, s3_client, bucket_names: list[str]) -> list[dict]:
        security: list[dict] = []

        for name in bucket_names:
            reasons: list[str] = []
            exposed = False

            try:
                acl = s3_client.get_bucket_acl(Bucket=name)
                for grant in acl.get("Grants", []):
                    grantee = grant.get("Grantee", {})
                    if grantee.get("URI") in PUBLIC_GRANTEE_URIS:
                        exposed = True
                        reasons.append("Bucket ACL allows public access")
                        break
            except ClientError as exc:
                reasons.append(f"ACL check skipped: {exc.response.get('Error', {}).get('Code', 'Unknown')}")

            try:
                status = s3_client.get_bucket_policy_status(Bucket=name)
                if status.get("PolicyStatus", {}).get("IsPublic", False):
                    exposed = True
                    reasons.append("Bucket policy is public")
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                if code not in {"NoSuchBucketPolicy", "AccessDenied"}:
                    reasons.append(f"Policy status check skipped: {code}")

            try:
                pab = s3_client.get_public_access_block(Bucket=name).get("PublicAccessBlockConfiguration", {})
                if not all(pab.get(flag, False) for flag in [
                    "BlockPublicAcls",
                    "IgnorePublicAcls",
                    "BlockPublicPolicy",
                    "RestrictPublicBuckets",
                ]):
                    exposed = True
                    reasons.append("Public access block is not fully enabled")
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                if code in {"NoSuchPublicAccessBlockConfiguration", "NoSuchPublicAccessBlockConfigurationException"}:
                    exposed = True
                    reasons.append("Public access block is not configured")
                elif code != "AccessDenied":
                    reasons.append(f"Public access block check skipped: {code}")

            security.append({"name": name, "is_exposed": exposed, "reasons": reasons})

        return security

    def _collect_iam_user_mfa(self, iam_client, user_names: list[str]) -> list[dict]:
        items: list[dict] = []

        for user_name in user_names:
            enabled = False
            try:
                devices = iam_client.list_mfa_devices(UserName=user_name).get("MFADevices", [])
                enabled = len(devices) > 0
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                items.append({"user_name": user_name, "mfa_enabled": False, "error": code})
                continue

            items.append({"user_name": user_name, "mfa_enabled": enabled})

        return items
