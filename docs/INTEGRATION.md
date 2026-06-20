# Integrating with Omni Identity (OIDC SSO)

Omni Identity is a hosted OpenID Connect provider. Applications send users to the
Omni Identity **hosted login page** to sign in, then receive an authorization
code they exchange for tokens. Passwords are only ever entered on Omni Identity —
never inside your application.

This guide shows how to add a **"Continue with Omni Identity"** button using the
Authorization Code flow with PKCE.

## 1. Register your application

In the Omni Identity admin console (**Applications → Register application**),
create a client and record:

- **Client ID** (and **Client Secret**, for confidential server-side apps)
- **Client type**: `public` (SPA / native / mobile — PKCE required, no secret) or
  `confidential` (server-side app that can keep a secret)
- **Allowed redirect URIs** — exact, absolute `https://` URLs. There is no
  wildcard matching; every callback URL must be listed verbatim.
- Optional display metadata shown on the login page: **Display name**, **Logo
  URL**, **Homepage URL**.
- Optional **Post-logout redirect URIs** for RP-initiated logout.
- **Trusted first-party** — when enabled, the consent screen is skipped.

## 2. Discover the endpoints

All endpoints are advertised at the discovery document:

```
GET https://<issuer>/.well-known/openid-configuration
```

Key endpoints:

| Purpose            | Endpoint                       |
| ------------------ | ------------------------------ |
| Authorization      | `/oauth2/authorize`            |
| Token              | `/oauth2/token`                |
| UserInfo           | `/userinfo`                    |
| JWKS               | `/jwks.json`                   |
| Revocation         | `/oauth2/revoke`               |
| End session (logout) | `/logout`                    |

## 3. Start the flow (Authorization Code + PKCE)

Generate a `code_verifier` and its `S256` `code_challenge`, plus random `state`
and `nonce` values, then redirect the browser to the authorization endpoint:

```
GET https://<issuer>/oauth2/authorize
  ?response_type=code
  &client_id=<your_client_id>
  &redirect_uri=<your_exact_redirect_uri>
  &scope=openid%20email%20profile
  &state=<random_state>
  &nonce=<random_nonce>
  &code_challenge=<base64url(sha256(code_verifier))>
  &code_challenge_method=S256
```

`code_challenge` is **required** for public clients. Omni Identity will show the
hosted login page ("Sign in to continue to *<your app>*"), authenticate the
user, optionally show a consent screen, and redirect back to your
`redirect_uri` with `code` and `state`.

Always verify the returned `state` matches what you sent.

## 4. Exchange the code for tokens

```
POST https://<issuer>/oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=<code>
&redirect_uri=<same_redirect_uri>
&client_id=<your_client_id>
&code_verifier=<original_code_verifier>
# confidential clients also send:
&client_secret=<your_client_secret>
```

The response contains `access_token`, `id_token`, and (with the
`offline_access` scope) a `refresh_token`. Validate the `id_token` signature
against `/jwks.json`, and check `iss`, `aud`, `exp`, and `nonce`.

## 5. The "Continue with Omni Identity" button

Drop-in HTML + CSS for a custom Omni app. The button does nothing but start the
standard redirect above — it never collects a password.

```html
<a class="omni-sso-btn" href="/auth/omni/start">
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"
       stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>
  </svg>
  <span>Continue with Omni Identity</span>
</a>

<style>
  .omni-sso-btn {
    display: inline-flex; align-items: center; gap: 10px;
    height: 44px; padding: 0 18px; border-radius: 8px;
    font: 600 15px/1 -apple-system, system-ui, sans-serif;
    color: #fff; background: #2f6fed; text-decoration: none;
    box-shadow: 0 1px 2px rgba(0,0,0,.2);
  }
  .omni-sso-btn:hover { background: #2a63d4; }
</style>
```

Alternative label text: **"Sign in with SSO"**.

`/auth/omni/start` is a route **in your app** that builds the PKCE values, stores
the `code_verifier` + `state` in the user's session, and 302-redirects to the
authorization endpoint. A minimal browser-side PKCE starter:

```js
// Generate PKCE + state, then redirect to Omni Identity.
async function startOmniLogin(issuer, clientId, redirectUri) {
  const rand = (n) => {
    const a = new Uint8Array(n); crypto.getRandomValues(a);
    return btoa(String.fromCharCode(...a)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  };
  const verifier = rand(32);
  const data = new TextEncoder().encode(verifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  const challenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  const state = rand(16), nonce = rand(16);

  // Persist verifier + state to validate the callback later.
  sessionStorage.setItem('omni_pkce_verifier', verifier);
  sessionStorage.setItem('omni_state', state);

  const url = new URL(issuer + '/oauth2/authorize');
  url.search = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: 'openid email profile',
    state, nonce,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  }).toString();
  window.location.assign(url.toString());
}
```

> For confidential apps, prefer doing PKCE generation and the token exchange on
> the server so the `client_secret` never reaches the browser.

## 6. Logout (RP-initiated)

Send the user to the end-session endpoint to clear their Omni Identity session:

```
GET https://<issuer>/logout
  ?id_token_hint=<the_id_token_you_received>
  &post_logout_redirect_uri=<an_allowlisted_uri>
  &state=<optional_state>
```

Omni Identity validates `id_token_hint`, clears the session, revokes the
browser's refresh tokens for your client, and (when `post_logout_redirect_uri`
exactly matches your registered allowlist) redirects back with `state`.
Otherwise it shows the branded "You've signed out" page.

## Security notes

- Redirect URIs and post-logout redirect URIs are matched **exactly**; no
  wildcards, no open redirects.
- Public clients **must** use PKCE (`S256`).
- Always validate `state` (CSRF) and the `id_token` (`iss`, `aud`, `exp`,
  `nonce`, signature).
- Never collect or store the user's Omni Identity password in your application.
