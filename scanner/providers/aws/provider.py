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
        result.data["service_status"] = {
            "s3": {"status": "PENDING", "errors": []},
            "iam": {"status": "PENDING", "errors": []},
            "ec2": {"status": "PENDING", "errors": []},
        }

        try:
            session = self._session()

            sts = session.client("sts")
            identity = sts.get_caller_identity()
            result.data["identity"] = {
                "account": identity["Account"],
                "arn": identity["Arn"],
                "user_id": identity["UserId"],
            }

            self._collect_s3(session, result)
            self._collect_iam(session, result)
            self._collect_security_groups(session, result)

        except ProfileNotFound:
            result.errors.append(f"AWS profile '{self.profile_name}' 을 찾을 수 없습니다.")
            self._mark_service_failed(result, "s3", "ProfileNotFound")
            self._mark_service_failed(result, "iam", "ProfileNotFound")
            self._mark_service_failed(result, "ec2", "ProfileNotFound")
        except NoCredentialsError:
            result.errors.append("AWS 자격 증명을 찾을 수 없습니다.")
            self._mark_service_failed(result, "s3", "NoCredentialsError")
            self._mark_service_failed(result, "iam", "NoCredentialsError")
            self._mark_service_failed(result, "ec2", "NoCredentialsError")
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            message = exc.response.get("Error", {}).get("Message", str(exc))
            result.errors.append(f"{code}: {message}")
            self._mark_service_failed(result, "s3", f"{code}: {message}")
            self._mark_service_failed(result, "iam", f"{code}: {message}")
            self._mark_service_failed(result, "ec2", f"{code}: {message}")
        except BotoCoreError as exc:
            result.errors.append(str(exc))
            self._mark_service_failed(result, "s3", str(exc))
            self._mark_service_failed(result, "iam", str(exc))
            self._mark_service_failed(result, "ec2", str(exc))
        except Exception as exc:
            result.errors.append(str(exc))
            self._mark_service_failed(result, "s3", str(exc))
            self._mark_service_failed(result, "iam", str(exc))
            self._mark_service_failed(result, "ec2", str(exc))

        return result

    def _collect_s3(self, session: boto3.Session, result: ScanResult) -> None:
        try:
            s3 = session.client("s3")
            buckets = s3.list_buckets().get("Buckets", [])
            bucket_names = [bucket["Name"] for bucket in buckets]
            result.data["s3_buckets"] = bucket_names
            result.data["s3_bucket_security"] = self._collect_s3_bucket_security(s3, bucket_names)
            self._mark_service_success(result, "s3")
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            message = exc.response.get("Error", {}).get("Message", str(exc))
            result.errors.append(f"S3 scan failed: {code}: {message}")
            result.data.setdefault("s3_buckets", [])
            result.data.setdefault("s3_bucket_security", [])
            self._mark_service_failed(result, "s3", f"{code}: {message}")

    def _collect_iam(self, session: boto3.Session, result: ScanResult) -> None:
        try:
            iam = session.client("iam")
            users = iam.list_users().get("Users", [])
            user_names = [user["UserName"] for user in users]
            result.data["iam_users"] = user_names
            result.data["iam_user_mfa"] = self._collect_iam_user_mfa(iam, user_names)
            result.data["iam_user_policy_risk"] = self._collect_iam_user_policy_risk(iam, user_names)
            self._mark_service_success(result, "iam")
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            message = exc.response.get("Error", {}).get("Message", str(exc))
            result.errors.append(f"IAM scan failed: {code}: {message}")
            result.data.setdefault("iam_users", [])
            result.data.setdefault("iam_user_mfa", [])
            result.data.setdefault("iam_user_policy_risk", [])
            self._mark_service_failed(result, "iam", f"{code}: {message}")

    def _collect_security_groups(self, session: boto3.Session, result: ScanResult) -> None:
        try:
            ec2 = session.client("ec2")
            groups = ec2.describe_security_groups().get("SecurityGroups", [])
            normalized: list[dict] = []
            for group in groups:
                ingress_rules: list[dict] = []
                for perm in group.get("IpPermissions", []):
                    cidrs = [entry.get("CidrIp") for entry in perm.get("IpRanges", []) if entry.get("CidrIp")]
                    cidrs.extend([entry.get("CidrIpv6") for entry in perm.get("Ipv6Ranges", []) if entry.get("CidrIpv6")])
                    ingress_rules.append(
                        {
                            "ip_protocol": perm.get("IpProtocol"),
                            "from_port": perm.get("FromPort"),
                            "to_port": perm.get("ToPort"),
                            "cidrs": cidrs,
                        }
                    )

                normalized.append(
                    {
                        "group_id": group.get("GroupId", ""),
                        "group_name": group.get("GroupName", ""),
                        "description": group.get("Description", ""),
                        "ingress_rules": ingress_rules,
                    }
                )

            result.data["security_groups"] = normalized
            self._mark_service_success(result, "ec2")
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            message = exc.response.get("Error", {}).get("Message", str(exc))
            result.errors.append(f"Security Group scan failed: {code}: {message}")
            result.data.setdefault("security_groups", [])
            self._mark_service_failed(result, "ec2", f"{code}: {message}")

    def _collect_s3_bucket_security(self, s3_client, bucket_names: list[str]) -> list[dict]:
        security: list[dict] = []

        for name in bucket_names:
            reasons: list[str] = []
            exposed = False
            encryption_enabled = True

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

            try:
                s3_client.get_bucket_encryption(Bucket=name)
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "Unknown")
                if code in {"ServerSideEncryptionConfigurationNotFoundError", "NoSuchServerSideEncryptionConfiguration"}:
                    encryption_enabled = False
                    reasons.append("Server-side encryption is not configured")
                elif code != "AccessDenied":
                    reasons.append(f"Encryption check skipped: {code}")

            security.append(
                {
                    "name": name,
                    "is_exposed": exposed,
                    "encryption_enabled": encryption_enabled,
                    "reasons": reasons,
                }
            )

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

    def _collect_iam_user_policy_risk(self, iam_client, user_names: list[str]) -> list[dict]:
        risks: list[dict] = []

        for user_name in user_names:
            user_risk = {"user_name": user_name, "wildcard_admin_policies": []}

            try:
                attached = iam_client.list_attached_user_policies(UserName=user_name).get("AttachedPolicies", [])
                for policy in attached:
                    arn = policy.get("PolicyArn", "")
                    version_doc = self._get_default_policy_document(iam_client, arn)
                    if self._has_wildcard_admin(version_doc):
                        user_risk["wildcard_admin_policies"].append(
                            {
                                "policy_name": policy.get("PolicyName", ""),
                                "policy_arn": arn,
                                "source": "managed",
                            }
                        )

                inline_names = iam_client.list_user_policies(UserName=user_name).get("PolicyNames", [])
                for policy_name in inline_names:
                    inline_doc = iam_client.get_user_policy(UserName=user_name, PolicyName=policy_name).get(
                        "PolicyDocument", {}
                    )
                    if self._has_wildcard_admin(inline_doc):
                        user_risk["wildcard_admin_policies"].append(
                            {
                                "policy_name": policy_name,
                                "policy_arn": "",
                                "source": "inline",
                            }
                        )

            except ClientError:
                pass

            risks.append(user_risk)

        return risks

    def _get_default_policy_document(self, iam_client, policy_arn: str) -> dict:
        policy = iam_client.get_policy(PolicyArn=policy_arn).get("Policy", {})
        default_version_id = policy.get("DefaultVersionId")
        if not default_version_id:
            return {}
        version = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=default_version_id)
        return version.get("PolicyVersion", {}).get("Document", {})

    def _has_wildcard_admin(self, document: dict) -> bool:
        statements = document.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            effect = stmt.get("Effect")
            if effect != "Allow":
                continue

            actions = stmt.get("Action", [])
            resources = stmt.get("Resource", [])
            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]

            if "*" in actions and "*" in resources:
                return True

        return False

    def _mark_service_success(self, result: ScanResult, service: str) -> None:
        status = result.data.setdefault("service_status", {}).setdefault(service, {"status": "PENDING", "errors": []})
        if status["status"] == "FAILED":
            status["status"] = "PARTIAL"
        elif status["status"] == "PENDING":
            status["status"] = "SUCCESS"

    def _mark_service_failed(self, result: ScanResult, service: str, message: str) -> None:
        status = result.data.setdefault("service_status", {}).setdefault(service, {"status": "PENDING", "errors": []})
        status["errors"].append(message)
        if status["status"] == "SUCCESS":
            status["status"] = "PARTIAL"
        else:
            status["status"] = "FAILED"
