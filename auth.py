import os
import secrets
import time
import urllib.parse
from typing import Dict, Optional
from functools import lru_cache

import httpx
import requests
from jose import jwt, jwk
from mcp.server.auth.provider import (
    OAuthAuthorizationServerProvider,
    AuthorizationParams,
    AuthorizationCode,
    RefreshToken,
    AccessToken,
    AuthorizeError,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from client_storage import load_clients, save_clients

# ---------------------------------------------------------------------------
# Environment configuration
# ---------------------------------------------------------------------------
AUTH0_DOMAIN = os.environ.get("AUTH0_DOMAIN", "")
AUTH0_CLIENT_ID = os.environ.get("AUTH0_CLIENT_ID", "")
AUTH0_CLIENT_SECRET = os.environ.get("AUTH0_CLIENT_SECRET", "")

AUTH0_AUTHORIZE_URL = f"https://{AUTH0_DOMAIN}/authorize"
AUTH0_TOKEN_URL = f"https://{AUTH0_DOMAIN}/oauth/token"
AUTH0_AUDIENCE = os.environ.get("AUTH0_AUDIENCE", AUTH0_CLIENT_ID)

AUTH0_CALLBACK_URL = os.environ.get("AUTH0_CALLBACK_URL", "http://localhost:8000/auth/callback")

# ---------------------------------------------------------------------------
# Simple in-memory storage – replace with a persistent backend for production
# ---------------------------------------------------------------------------
_authorization_codes: Dict[str, AuthorizationCode] = {}
_refresh_tokens: Dict[str, RefreshToken] = {}
_access_tokens: Dict[str, AccessToken] = {}
_pending: Dict[str, dict] = {}
_auth_by_code: Dict[str, dict] = {}
_auth_tokens_map: Dict[str, dict] = {}
_applicant_ids: Dict[str, str] = {}  # Map access tokens to applicant IDs

# Load clients on startup and ensure defaults
_clients: Dict[str, OAuthClientInformationFull] = {}


@lru_cache()
def _get_jwks():
    """Cache JWKS to avoid repeated fetches."""
    resp = requests.get(f"https://{AUTH0_DOMAIN}/.well-known/jwks.json")
    return resp.json()["keys"]

def _get_signing_key(token: str):
    """Get the signing key for a JWT token from JWKS."""
    # Decode the JWT header to get the key ID and algorithm
    unverified_header = jwt.get_unverified_header(token)
    kid = unverified_header.get("kid")
    token_alg = unverified_header.get("alg", "RS256")
    
    # Get all available keys
    jwks = _get_jwks()
    
    if kid:
        # If we have a kid, find the specific key
        for key in jwks:
            if key.get("kid") == kid:
                key_alg = key.get("alg", token_alg)
                return jwk.construct(key), key_alg
        raise ValueError(f"Unable to find a signing key that matches: '{kid}'")
    else:
        # If no kid, use the first available key
        # This is common when there's only one signing key
        if jwks:
            key = jwks[0]
            key_alg = key.get("alg", token_alg)
            return jwk.construct(key), key_alg
        
        raise ValueError("No keys available in JWKS")

def extract_applicant_id(auth0_claims: dict) -> str:
    """Extract applicant_id from Auth0 token claims."""
    # Try custom claim first, then fallback to sub
    return auth0_claims.get("applicant_id") or auth0_claims.get("sub", "")

def get_applicant_id_from_token(access_token: str) -> Optional[str]:
    """Get applicant_id for a given access token."""
    return _applicant_ids.get(access_token)

# ---------------------------------------------------------------------------
# Provider implementation (BROKER pattern – delegates login to Auth0)
# ---------------------------------------------------------------------------
class Auth0Provider(
    OAuthAuthorizationServerProvider[
        AuthorizationCode, RefreshToken, AccessToken
    ]
):
    """Auth0-backed OAuth Authorization Server provider for FastMCP.

    This implementation lets the MCP server behave as a *complete* OAuth 2.0
    Authorization Server for its clients while *delegating* the interactive
    login step to Auth0.  The flow is sometimes called the **broker pattern**.

    Sequence of calls (Authorization Code + PKCE):

        +---------+        1. /authorize          +-----------------+
        | Client  | ----------------------------> |  MCP /authorize |
        +---------+                                +-----------------+
             ^                                             |
             | (3) 302 with Auth0 URL                     |
             +---------------------------------------------+
                                                           v
                                                +-------------------+
                                            4.  |  Auth0 /authorize |
                                                +-------------------+
                                                           |
                                                           | 5. user login
                                                           v
                                                +-------------------+
                                            6.  |  /auth/callback   |
                                                +-------------------+
                                                           |
             +---------------------------------------------+
             | 7. 302 back to client with MCP code         |
        +---------+                                +-----------------+
        | Client  | <----------------------------  |  MCP callback   |
        +---------+                                +-----------------+
             |
        8. /token (MCP code)   -->  MCP exchanges code for local
                                   access/refresh tokens which map
                                   to Auth0 tokens under the hood.

    After this exchange the MCP-issued access token is presented in the
    "Authorization: Bearer" header for protected tool calls, and
    `load_access_token()` transparently validates either local tokens or
    raw Auth0 JWTs.
    """ 

    # ------------------------------------------------------------------
    # Dynamic client registration (optional)
    # ------------------------------------------------------------------
    async def get_client(self, client_id: str) -> Optional[OAuthClientInformationFull]:
        """Get client information by client_id"""
        return _clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        """Register a new OAuth client dynamically"""
        # For MCP Inspector and dynamic registration, allow overwriting existing clients
        _clients[client_info.client_id] = client_info
        # Save to persistent storage
        save_clients(_clients)

    # ------------------------------------------------------------------
    # Authorization endpoint – implemented
    # ------------------------------------------------------------------
    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        """Return Auth0 /authorize URL and stash request context."""
        # Use the client's state parameter (or generate one if not provided)
        state = params.state or secrets.token_urlsafe(16)

        # Save request context using the same state that will be used throughout
        _pending[state] = {
            "client_id": client.client_id,
            "redirect_uri": params.redirect_uri,
            "scopes": params.scopes or [],
            "code_challenge": params.code_challenge,
            "issued_at": time.time(),
        }

        query = {
            "response_type": "code",
            "client_id": AUTH0_CLIENT_ID,
            "redirect_uri": AUTH0_CALLBACK_URL,
            "scope": "openid profile email " + " ".join(params.scopes or []),
            "state": state,  # Use the same state throughout the flow
        }
        # Temporarily disable PKCE for Auth0 to get the flow working
        # if params.code_challenge:
        #     query["code_challenge"] = params.code_challenge
        #     query["code_challenge_method"] = "S256"
        
        auth_url = AUTH0_AUTHORIZE_URL + "?" + urllib.parse.urlencode(query)
        return auth_url

    async def handle_auth0_callback(self, state: str, auth0_code: str) -> str:
        """Finish Auth0 flow, create local authorization code, redirect."""
        
        # Clean up expired states (older than 10 minutes)
        current_time = time.time()
        expired_states = [s for s, ctx in _pending.items() if current_time - ctx.get('issued_at', 0) > 600]
        for expired_state in expired_states:
            _pending.pop(expired_state, None)
        
        # Load state data from memory
        ctx = _pending.pop(state, None)
        if not ctx:
            raise AuthorizeError("invalid_request", "Unknown or expired state")

        # Check if state is expired (older than 10 minutes)
        if current_time - ctx.get('issued_at', 0) > 600:
            raise AuthorizeError("invalid_request", "Expired state")
        
        # Don't exchange with Auth0 yet - store the Auth0 code for later
        # We'll exchange it when the MCP client provides the code_verifier
        local_code = secrets.token_urlsafe(32)
        auth_code = AuthorizationCode(
            code=local_code,
            scopes=ctx["scopes"],
            expires_at=time.time() + 600,
            client_id=ctx["client_id"],
            code_challenge=ctx["code_challenge"],
            redirect_uri=ctx["redirect_uri"],
            redirect_uri_provided_explicitly=True,
        )
        
        # Store authorization code in memory
        _authorization_codes[local_code] = auth_code

        # Store the Auth0 code to exchange later when we have the code_verifier
        _auth_by_code[local_code] = {
            "auth0_code": auth0_code,
            "state": state
        }
        
        redirect_url = construct_redirect_uri(str(ctx["redirect_uri"]), code=local_code, state=state)
        
        # Redirect to original redirect_uri with our local authorization code and same state
        return redirect_url

    # ------------------------------------------------------------------
    # Authorization code helpers – placeholders
    # ------------------------------------------------------------------
    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> Optional[AuthorizationCode]:
        return _authorization_codes.get(authorization_code)

    async def exchange_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: AuthorizationCode,
    ) -> OAuthToken:
        auth_data = _auth_by_code.pop(authorization_code.code, None)
        if not auth_data:
            raise TokenError("invalid_grant", "Unknown code")

        auth0_code = auth_data.get("auth0_code")
        if not auth0_code:
            raise TokenError("invalid_grant", "Missing Auth0 code")
        
        # Now exchange the Auth0 code for tokens
        # Note: We need the code_verifier from the MCP client, but the current
        # MCP SDK doesn't provide it in this method. For now, we'll try without it
        # and see if Auth0 accepts it.
        
        async with httpx.AsyncClient() as client_http:
            token_data = {
                "grant_type": "authorization_code",
                "client_id": AUTH0_CLIENT_ID,
                "client_secret": AUTH0_CLIENT_SECRET,
                "code": auth0_code,
                "redirect_uri": AUTH0_CALLBACK_URL,
            }
            
            # If we have a code_challenge, we need the corresponding code_verifier
            # For now, let's see if the exchange works without PKCE
            
            resp = await client_http.post(AUTH0_TOKEN_URL, data=token_data)
            
        if resp.status_code != 200:
            error_details = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else resp.text
            raise TokenError("invalid_grant", f"Auth0 code exchange failed: {error_details}")
            
        tok = resp.json()

        # Extract applicant_id from Auth0 access token if available
        auth0_access_token = tok.get("access_token")
        applicant_id = None
        if auth0_access_token:
            try:
                # Check if token looks like a JWT (has 3 parts separated by dots)
                token_parts = auth0_access_token.split('.')
                
                if len(token_parts) != 3:
                    # This might be an opaque token, we can't extract claims from it
                    # Try to get user info from Auth0's userinfo endpoint
                    try:
                        async with httpx.AsyncClient() as userinfo_client:
                            userinfo_resp = await userinfo_client.get(
                                f"https://{AUTH0_DOMAIN}/userinfo",
                                headers={"Authorization": f"Bearer {auth0_access_token}"}
                            )
                        if userinfo_resp.status_code == 200:
                            userinfo = userinfo_resp.json()
                            applicant_id = extract_applicant_id(userinfo)
                    except Exception as userinfo_error:
                        pass
                else:
                    # Try to decode as JWT
                    unverified_header = jwt.get_unverified_header(auth0_access_token)
                    
                    token_alg = unverified_header.get("alg")
                    if token_alg == "dir":
                        # Try to get user info from Auth0's userinfo endpoint instead
                        try:
                            async with httpx.AsyncClient() as userinfo_client:
                                userinfo_resp = await userinfo_client.get(
                                    f"https://{AUTH0_DOMAIN}/userinfo",
                                    headers={"Authorization": f"Bearer {auth0_access_token}"}
                                )
                            if userinfo_resp.status_code == 200:
                                userinfo = userinfo_resp.json()
                                applicant_id = extract_applicant_id(userinfo)
                        except Exception as userinfo_error:
                            pass
                    else:
                        # Decode Auth0 JWT to extract applicant_id
                        signing_key, key_alg = _get_signing_key(auth0_access_token)
                        claims = jwt.decode(
                            auth0_access_token,
                            signing_key,
                            algorithms=[key_alg],
                            audience=AUTH0_AUDIENCE,
                            issuer=f"https://{AUTH0_DOMAIN}/",
                        )
                        applicant_id = extract_applicant_id(claims)
            except Exception as e:
                # If we can't decode the token, continue without applicant_id
                pass

        # create local tokens
        access_token = secrets.token_urlsafe(32)
        refresh_token = secrets.token_urlsafe(32)

        at = AccessToken(
            token=access_token,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=int(time.time()) + tok.get("expires_in", 3600),
        )
        rt = RefreshToken(
            token=refresh_token,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
        )
        _access_tokens[access_token] = at
        _refresh_tokens[refresh_token] = rt
        _auth_tokens_map[refresh_token] = tok  # Map refresh token to auth0 data
        
        # Store applicant_id mapping if available
        if applicant_id:
            _applicant_ids[access_token] = applicant_id
            
        oauth_token = OAuthToken(access_token=access_token, refresh_token=refresh_token, expires_in=3600)
        
        return oauth_token

    # ------------------------------------------------------------------
    # Refresh token helpers – placeholders
    # ------------------------------------------------------------------
    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> Optional[RefreshToken]:
        return _refresh_tokens.get(refresh_token)

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        # get auth0 refresh token from map
        auth_data = _auth_tokens_map.get(refresh_token.token)
        if not auth_data:
            raise TokenError("invalid_grant", "Unknown refresh token")

        auth0_refresh = auth_data.get("refresh_token")
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                AUTH0_TOKEN_URL,
                data={
                    "grant_type": "refresh_token",
                    "client_id": AUTH0_CLIENT_ID,
                    "client_secret": AUTH0_CLIENT_SECRET,
                    "refresh_token": auth0_refresh,
                },
            )
        if resp.status_code != 200:
            raise TokenError("invalid_grant", "Auth0 refresh failed")
        new_tok = resp.json()

        new_access = secrets.token_urlsafe(32)
        _access_tokens[new_access] = AccessToken(
            token=new_access,
            client_id=client.client_id,
            scopes=scopes or refresh_token.scopes,
            expires_at=int(time.time()) + new_tok.get("expires_in", 3600),
        )
        # Update the auth data with new tokens
        _auth_tokens_map[refresh_token.token] = new_tok
        return OAuthToken(access_token=new_access, refresh_token=refresh_token.token, expires_in=3600)

    # ------------------------------------------------------------------
    # Access token validation – implemented so protected tools can work
    # ------------------------------------------------------------------
    async def load_access_token(self, token: str) -> Optional[AccessToken]:
        # First check if we have an internally issued token in memory
        if token in _access_tokens:
            return _access_tokens[token]

        # Otherwise assume it's a raw Auth0 JWT and attempt to validate it
        try:
            # Get the proper signing key for this token
            signing_key, key_alg = _get_signing_key(token)
            claims = jwt.decode(
                token,
                signing_key,
                algorithms=[key_alg],
                audience=AUTH0_AUDIENCE,
                issuer=f"https://{AUTH0_DOMAIN}/",
            )

            # Extract applicant_id from Auth0 claims
            applicant_id = extract_applicant_id(claims)

            # Wrap JWT in the AccessToken dataclass so MCP SDK is happy
            at = AccessToken(
                token=token,
                client_id=claims.get("azp", ""),
                scopes=claims.get("scope", "").split(),
                expires_at=claims.get("exp"),
            )
            
            # Store applicant_id mapping for use in Truv API calls
            if applicant_id:
                _applicant_ids[token] = applicant_id
                
            # Optionally cache
            _access_tokens[token] = at
            return at
        except Exception:  # noqa: BLE001
            return None

    # ------------------------------------------------------------------
    # Revocation – placeholder
    # ------------------------------------------------------------------
    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        tkn = getattr(token, "token", "")
        _access_tokens.pop(tkn, None)
        _refresh_tokens.pop(tkn, None)
        _auth_tokens_map.pop(tkn, None)
        _applicant_ids.pop(tkn, None)  # Clean up applicant_id mapping 