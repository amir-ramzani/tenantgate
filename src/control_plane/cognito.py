"""Wrapper over the Cognito admin APIs the control plane needs.

Every call here is a write. Only the primary Region's control plane makes them
(single writer), and callers check the degraded-mode flag before getting this far.

``UpdateUserPoolClient`` and ``UpdateResourceServer`` reset omitted fields to
their defaults, so clients are always rendered from one canonical parameter
builder and resource-server scopes are read-modify-written in full.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from aws_lambda_powertools import Logger
from botocore.exceptions import ClientError

from authlib_mt.scopes import ACTIONS, generic_scope, tenant_scope, tenant_scope_name

logger = Logger(service="tenantgate-control-plane", child=True)

THROTTLING = frozenset({"TooManyRequestsException", "LimitExceededException"})
USER_SCOPES = ("openid", "email", "profile")


class CognitoThrottled(Exception):
    """Cognito is rate limiting us even after boto3's adaptive retries."""


@dataclass(frozen=True)
class CreatedClient:
    client_id: str
    client_secret: str | None = None


@dataclass(frozen=True)
class CognitoUser:
    username: str
    sub: str
    email: str | None
    created: bool = False


def error_code(err: ClientError) -> str:
    return str(err.response.get("Error", {}).get("Code", ""))


class CognitoAdmin:
    def __init__(
        self,
        client: Any,
        user_pool_id: str,
        *,
        resource_server_id: str = "api",
        access_token_minutes: int = 60,
        refresh_token_days: int = 30,
        managed_login_branding: bool = True,
    ) -> None:
        self._c = client
        self._pool = user_pool_id
        self._rs = resource_server_id
        self._access_minutes = access_token_minutes
        self._refresh_days = refresh_token_days
        self._branding = managed_login_branding

    @property
    def resource_server_id(self) -> str:
        return self._rs

    def _call(self, op: str, **params: Any) -> Any:
        try:
            return getattr(self._c, op)(**params)
        except ClientError as err:
            if error_code(err) in THROTTLING:
                raise CognitoThrottled(op) from err
            raise

    # ------------------------------------------------------------ user (PKCE) clients

    def user_client_params(
        self,
        tenant_id: str,
        *,
        callback_urls: list[str],
        logout_urls: list[str],
        identity_providers: list[str],
        enabled: bool = True,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "UserPoolId": self._pool,
            "ClientName": f"tenant-{tenant_id}",
            "ExplicitAuthFlows": ["ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
            "PreventUserExistenceErrors": "ENABLED",
            "EnableTokenRevocation": True,
            "AccessTokenValidity": self._access_minutes,
            "IdTokenValidity": self._access_minutes,
            "RefreshTokenValidity": self._refresh_days,
            "TokenValidityUnits": {
                "AccessToken": "minutes",
                "IdToken": "minutes",
                "RefreshToken": "days",
            },
            "SupportedIdentityProviders": identity_providers or ["COGNITO"],
        }
        if enabled:
            params |= {
                "AllowedOAuthFlowsUserPoolClient": True,
                "AllowedOAuthFlows": ["code"],  # PKCE is enforced by managed login
                "AllowedOAuthScopes": [
                    *USER_SCOPES,
                    *(generic_scope(a, self._rs) for a in ACTIONS),
                ],
                "CallbackURLs": callback_urls,
                "LogoutURLs": logout_urls,
            }
        else:
            # Disabled tenant: no OAuth flows. Refresh still "works" at the API level
            # but pre-token-generation denies it for disabled tenants.
            params |= {
                "AllowedOAuthFlowsUserPoolClient": False,
                "ExplicitAuthFlows": ["ALLOW_REFRESH_TOKEN_AUTH"],
            }
        return params

    def create_user_client(
        self,
        tenant_id: str,
        *,
        callback_urls: list[str],
        logout_urls: list[str],
        identity_providers: list[str],
    ) -> CreatedClient:
        resp = self._call(
            "create_user_pool_client",
            **self.user_client_params(
                tenant_id,
                callback_urls=callback_urls,
                logout_urls=logout_urls,
                identity_providers=identity_providers,
            ),
        )
        client_id = str(resp["UserPoolClient"]["ClientId"])
        self._apply_branding(client_id)
        return CreatedClient(client_id)

    def update_user_client(
        self,
        client_id: str,
        tenant_id: str,
        *,
        callback_urls: list[str],
        logout_urls: list[str],
        identity_providers: list[str],
        enabled: bool,
    ) -> None:
        params = self.user_client_params(
            tenant_id,
            callback_urls=callback_urls,
            logout_urls=logout_urls,
            identity_providers=identity_providers,
            enabled=enabled,
        )
        self._call("update_user_pool_client", ClientId=client_id, **params)

    def _apply_branding(self, client_id: str) -> None:
        """Managed login v2 only renders for clients with a branding style."""
        if not self._branding:
            return
        self._call(
            "create_managed_login_branding",
            UserPoolId=self._pool,
            ClientId=client_id,
            UseCognitoProvidedValues=True,
        )

    def delete_client(self, client_id: str) -> None:
        try:
            self._call("delete_user_pool_client", UserPoolId=self._pool, ClientId=client_id)
        except ClientError as err:
            if error_code(err) != "ResourceNotFoundException":
                raise

    # ------------------------------------------------------------ M2M clients + scopes

    def _resource_server(self) -> dict[str, Any]:
        resp = self._call("describe_resource_server", UserPoolId=self._pool, Identifier=self._rs)
        return dict(resp["ResourceServer"])

    def _put_scopes(self, server: dict[str, Any], scopes: list[dict[str, str]]) -> None:
        self._call(
            "update_resource_server",
            UserPoolId=self._pool,
            Identifier=self._rs,
            Name=server.get("Name", self._rs),
            Scopes=scopes,
        )

    def ensure_tenant_scopes(self, tenant_id: str) -> None:
        server = self._resource_server()
        scopes = list(server.get("Scopes", []))
        have = {s["ScopeName"] for s in scopes}
        added = False
        for action in ACTIONS:
            name = tenant_scope_name(tenant_id, action)
            if name not in have:
                scopes.append({"ScopeName": name, "ScopeDescription": f"{action} {tenant_id}"})
                added = True
        if added:
            self._put_scopes(server, scopes)

    def remove_tenant_scopes(self, tenant_id: str) -> None:
        server = self._resource_server()
        prefix = f"tenant.{tenant_id}."
        scopes = [s for s in server.get("Scopes", []) if not s["ScopeName"].startswith(prefix)]
        if len(scopes) != len(server.get("Scopes", [])):
            self._put_scopes(server, scopes)

    def create_m2m_client(self, tenant_id: str, name: str, actions: list[str]) -> CreatedClient:
        resp = self._call(
            "create_user_pool_client",
            UserPoolId=self._pool,
            ClientName=f"tenant-{tenant_id}-m2m-{name}"[:128],
            GenerateSecret=True,
            AllowedOAuthFlowsUserPoolClient=True,
            AllowedOAuthFlows=["client_credentials"],
            AllowedOAuthScopes=[tenant_scope(tenant_id, a, self._rs) for a in actions],
            AccessTokenValidity=self._access_minutes,
            TokenValidityUnits={"AccessToken": "minutes"},
            EnableTokenRevocation=True,
        )
        c = resp["UserPoolClient"]
        return CreatedClient(str(c["ClientId"]), str(c.get("ClientSecret") or "") or None)

    def set_m2m_client_enabled(
        self, client_id: str, tenant_id: str, name: str, actions: list[str], *, enabled: bool
    ) -> None:
        params: dict[str, Any] = {
            "UserPoolId": self._pool,
            "ClientId": client_id,
            "ClientName": f"tenant-{tenant_id}-m2m-{name}"[:128],
            "AccessTokenValidity": self._access_minutes,
            "TokenValidityUnits": {"AccessToken": "minutes"},
            "EnableTokenRevocation": True,
            "AllowedOAuthFlowsUserPoolClient": enabled,
        }
        if enabled:
            params |= {
                "AllowedOAuthFlows": ["client_credentials"],
                "AllowedOAuthScopes": [tenant_scope(tenant_id, a, self._rs) for a in actions],
            }
        self._call("update_user_pool_client", **params)

    # ------------------------------------------------------------ users

    @staticmethod
    def _attrs(attributes: list[dict[str, str]]) -> dict[str, str]:
        return {a["Name"]: a["Value"] for a in attributes}

    def get_user(self, username: str) -> CognitoUser | None:
        try:
            resp = self._call("admin_get_user", UserPoolId=self._pool, Username=username)
        except ClientError as err:
            if error_code(err) == "UserNotFoundException":
                return None
            raise
        attrs = self._attrs(resp.get("UserAttributes", []))
        return CognitoUser(str(resp["Username"]), attrs["sub"], attrs.get("email"))

    def find_user_by_sub(self, sub: str) -> CognitoUser | None:
        resp = self._call("list_users", UserPoolId=self._pool, Filter=f'sub = "{sub}"', Limit=1)
        users = resp.get("Users", [])
        if not users:
            return None
        attrs = self._attrs(users[0].get("Attributes", []))
        return CognitoUser(str(users[0]["Username"]), attrs.get("sub", sub), attrs.get("email"))

    def invite_user(self, email: str) -> CognitoUser:
        """Return the existing user for ``email`` or create one (Cognito emails the invite)."""
        existing = self.get_user(email)
        if existing is not None:
            return existing
        resp = self._call(
            "admin_create_user",
            UserPoolId=self._pool,
            Username=email,
            UserAttributes=[
                {"Name": "email", "Value": email},
                {"Name": "email_verified", "Value": "true"},
            ],
            DesiredDeliveryMediums=["EMAIL"],
        )
        user = resp["User"]
        attrs = self._attrs(user.get("Attributes", []))
        return CognitoUser(str(user["Username"]), attrs["sub"], email, created=True)

    def delete_user(self, username: str) -> None:
        try:
            self._call("admin_delete_user", UserPoolId=self._pool, Username=username)
        except ClientError as err:
            if error_code(err) != "UserNotFoundException":
                raise

    def global_sign_out(self, username: str) -> None:
        """Revoke refresh tokens (access tokens live until they expire)."""
        try:
            self._call("admin_user_global_sign_out", UserPoolId=self._pool, Username=username)
        except ClientError as err:
            if error_code(err) != "UserNotFoundException":
                raise
