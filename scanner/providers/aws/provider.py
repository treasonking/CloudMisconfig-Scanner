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

    def __init__(
        self,
        region_name: str = "ap-northeast-2",
        profile_name: str | None = "default",
        role_arn: str | None = None,
        external_id: str | None = None,
        role_session_name: str = "cloudmisconfig-scanner",
    ):
        self.region_name = region_name
        self.profile_name = profile_name
        self.role_arn = role_arn
        self.external_id = external_id
        self.role_session_name = role_session_name

    def _base_session(self) -> boto3.Session:
        if self.profile_name:
            return boto3.Session(profile_name=self.profile_name, region_name=self.region_name)
        return boto3.Session(region_name=self.region_name)

    def _session(self) -> boto3.Session:
        base = self._base_session()
        if not self.role_arn:
            return base

        sts = base.client("sts")
        assume_args = {
            "RoleArn": self.role_arn,
            "RoleSessionName": self.role_session_name,
        }
        if self.external_id:
            assume_args["ExternalId"] = self.external_id
        creds = sts.assume_role(**assume_args)["Credentials"]

        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=self.region_name,
        )

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
            if self.role_arn:
                result.data["assume_role"] = {
                    "role_arn": self.role_arn,
                    "source_profile": self.profile_name,
                    "external_id": self.external_id,
                }

            self._collect_s3(session, result)
            self._collect_iam(session, result)
            self._collect_security_groups(session, result)

        except ProfileNotFound:
            result.errors.append(f"AWS profile '{self.profile_name}' 을 찾을 수 없습니다.")
            self._mark_all_services_failed(result, "ProfileNotFound")
        except NoCredentialsError:
            result.errors.append("AWS 자격 증명을 찾을 수 없습니다.")
            self._mark_all_services_failed(result, "NoCredentialsError")
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            message = exc.response.get("Error", {}).get("Message", str(exc))
            msg = f"{code}: {message}"
            result.errors.append(msg)
            self._mark_all_services_failed(result, msg)
        except BotoCoreError as exc:
            result.errors.append(str(exc))
            self._mark_all_services_failed(result, str(exc))
        except Exception as exc:
            result.errors.append(str(exc))
            self._mark_all_services_failed(result, str(exc))

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

            users = self._paginate(iam, "list_users", "Users")
            user_names = [user["UserName"] for user in users]
            result.data["iam_users"] = user_names
            result.data["iam_user_mfa"] = self._collect_iam_user_mfa(iam, user_names)
            result.data["iam_user_policy_risk"] = self._collect_iam_user_policy_risk(iam, user_names)

            roles = self._paginate(iam, "list_roles", "Roles")
            role_names = [role["RoleName"] for role in roles]
            result.data["iam_roles"] = role_names
            result.data["iam_role_trust_risk"] = self._collect_iam_role_trust_risk(roles)
            result.data["iam_role_policy_risk"] = self._collect_iam_role_policy_risk(iam, role_names)

            self._mark_service_success(result, "iam")
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            message = exc.response.get("Error", {}).get("Message", str(exc))
            result.errors.append(f"IAM scan failed: {code}: {message}")
            result.data.setdefault("iam_users", [])
            result.data.setdefault("iam_user_mfa", [])
            result.data.setdefault("iam_user_policy_risk", [])
            result.data.setdefault("iam_roles", [])
            result.data.setdefault("iam_role_trust_risk", [])
            result.data.setdefault("iam_role_policy_risk", [])
            self._mark_service_failed(result, "iam", f"{code}: {message}")

    def _collect_security_groups(self, session: boto3.Session, result: ScanResult) -> None:
        try:
            ec2 = session.client("ec2")
            groups = self._paginate(ec2, "describe_security_groups", "SecurityGroups")
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
                if not all(
                    pab.get(flag, False)
                    for flag in ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]
                ):
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
                attached = self._paginate(iam_client, "list_attached_user_policies", "AttachedPolicies", UserName=user_name)
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

                inline_names = self._paginate(iam_client, "list_user_policies", "PolicyNames", UserName=user_name)
                for policy_name in inline_names:
                    inline_doc = iam_client.get_user_policy(UserName=user_name, PolicyName=policy_name).get("PolicyDocument", {})
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

    def _collect_iam_role_trust_risk(self, roles: list[dict]) -> list[dict]:
        items: list[dict] = []
        for role in roles:
            role_name = role.get("RoleName", "")
            trust_doc = role.get("AssumeRolePolicyDocument", {})
            risky = self._is_trust_policy_open(trust_doc)
            items.append(
                {
                    "role_name": role_name,
                    "open_trust": risky,
                    "evidence": trust_doc if risky else {},
                }
            )
        return items

    def _collect_iam_role_policy_risk(self, iam_client, role_names: list[str]) -> list[dict]:
        risks: list[dict] = []
        for role_name in role_names:
            role_risk = {"role_name": role_name, "wildcard_admin_policies": []}
            try:
                attached = self._paginate(iam_client, "list_attached_role_policies", "AttachedPolicies", RoleName=role_name)
                for policy in attached:
                    arn = policy.get("PolicyArn", "")
                    version_doc = self._get_default_policy_document(iam_client, arn)
                    if self._has_wildcard_admin(version_doc):
                        role_risk["wildcard_admin_policies"].append(
                            {
                                "policy_name": policy.get("PolicyName", ""),
                                "policy_arn": arn,
                                "source": "managed",
                            }
                        )

                inline_names = self._paginate(iam_client, "list_role_policies", "PolicyNames", RoleName=role_name)
                for policy_name in inline_names:
                    inline_doc = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name).get("PolicyDocument", {})
                    if self._has_wildcard_admin(inline_doc):
                        role_risk["wildcard_admin_policies"].append(
                            {
                                "policy_name": policy_name,
                                "policy_arn": "",
                                "source": "inline",
                            }
                        )
            except ClientError:
                pass
            risks.append(role_risk)
        return risks

    def _paginate(self, client, operation_name: str, result_key: str, **kwargs) -> list:
        paginator = client.get_paginator(operation_name)
        items: list = []
        for page in paginator.paginate(**kwargs):
            items.extend(page.get(result_key, []))
        return items

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
            if stmt.get("Effect") != "Allow":
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

    def _is_trust_policy_open(self, document: dict) -> bool:
        statements = document.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            principal = stmt.get("Principal", {})
            if principal == "*":
                return True
            if isinstance(principal, dict):
                for value in principal.values():
                    if value == "*":
                        return True
                    if isinstance(value, list) and "*" in value:
                        return True
        return False

    def _mark_all_services_failed(self, result: ScanResult, message: str) -> None:
        for service in ["s3", "iam", "ec2"]:
            self._mark_service_failed(result, service, message)

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
