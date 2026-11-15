# DSH Mobile: passkey + content-encryption server components

- Status: **design only — nothing here is installed on srv-main.** The app side (this
  fork, branch `feat/passkey-content-encryption`) is built against this contract, and
  every call it makes answers 404 until the components below exist. The app treats 404
  as "not installed", not as a failure, and keeps working on the password + token path.
- Date: 2026-11-15. Server: srv-main (Ubuntu ARM, `130.61.23.6`), DSH 0.2.1-rc.2,
  `dsh-web` on `127.0.0.1:3080`, nginx at `https://wuh30617.dpdns.org/dsh/` with Basic
  Auth (user `dsh`) + rotating launch token + cookie auth. DeepSeek API is out of money
  (402), so no model reply is possible until it is topped up — none of the verification
  below needs a model reply.
- App-side contract: `PasskeyGateway` (`app/src/main/.../security/PasskeyGateway.kt`)
  calls the endpoints in §2/§3. The wire format, the error shape and the cookie handover
  are fixed there; this document fixes the server side to match.

## 1. Where the components sit

One small service, not a DSH plugin and not a change to DSH itself:

- **A tiny gateway on srv-main**, e.g. a Node.js (or Go, or Python) process bound to
  `127.0.0.1` on a port only nginx reaches (say `127.0.0.1:3090`), run as `museops`
  under systemd (`dsh-security-gateway.service`, restart on failure, no public port).
- **nginx** gains two locations under the existing `/dsh/` prefix, both behind the
  same `auth_basic` as everything else:
  - `/dsh/passkey/` → the gateway (registration, login, key list/revoke, status)
  - `/dsh/content/` → the gateway (decryptor status, re-pairing)
- **The content decryptor is the same process, second job**: it also sits between
  nginx and DSH for `/api` POSTs that carry encrypted prompts — either as an nginx
  `auth_request`-style filter, or as a reverse-proxy hop (`/dsh/api/` → gateway →
  `127.0.0.1:3080/api/`). It decrypts `dsh-enc-v1:` envelopes before DSH sees them
  and (optionally, later) re-encrypts DSH's replies for the phone. See §3.
- **Why a gateway, not a DSH (Cordis) plugin:** DSH has no WebAuthn support and no
  hook to run before its own RPC layer; a plugin would have to be written against
  DSH's undocumented internals and would ride every DSH upgrade. The gateway only
  depends on three stable facts: nginx can proxy a subpath, the launch token is in
  the dsh-web log (the existing `~/bin/dsh-token-refresh.sh` already reads it), and
  the DSH session cookie is issued by `GET /?token=…`. If DSH's internals change, the
  gateway does not care.

## 2. Passkey verifier

### 2.1 What it stores

One file, `museops`-only, e.g. `/home/museops/dsh-security/passkeys.json` (mode
`0600`, owner `museops`):

```json
{
  "version": 1,
  "rpId": "wuh30617.dpdns.org",
  "keys": [
    {
      "credentialId": "<base64url>",
      "userHandle": "<base64url>",
      "userName": "dsh",
      "publicKeyJwk": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…" },
      "signCount": 0,
      "createdAt": 1720000000000,
      "lastUsedAt": 1720000000000,
      "label": "vivo X200 Pro mini"
    }
  ]
}
```

- Only public keys. A stolen copy of this file cannot sign anything — that is the
  whole point of a passkey. Back it up with the rest of `museops`' home; losing it
  means re-registering, not losing access (the dsh password still works).
- One key per device is the expected shape; several may exist (old phone + new phone).
  `signCount` is stored and checked (must not go backwards — a replayed assertion
  reuses an old counter).
- Challenges live in memory only, with a 60-second expiry, keyed by a random session
  id the app sends back with the finish call. Never persisted, never logged.

### 2.2 Endpoints (all under `/dsh/passkey/`, all behind nginx Basic Auth)

| Method & path | Auth | Request | Response |
|---|---|---|---|
| `GET /passkey/status` | proxy Basic | — | `{"installed":true}` |
| `POST /passkey/register/begin` | proxy Basic + DSH cookie | `{}` | `{"challenge","userId","userName":"dsh","rpId","excludeCredentials":[{"id"}]}` |
| `POST /passkey/register/finish` | proxy Basic + DSH cookie | `{"id","rawId","attestationObject","clientDataJSON"}` | `200 {"ok":true}` |
| `POST /passkey/login/begin` | proxy Basic | `{}` | `{"challenge","rpId","allowCredentials":[{"id"}]}` |
| `POST /passkey/login/finish` | proxy Basic | `{"id","rawId","authenticatorData","clientDataJSON","signature","userHandle?"}` | `200` + `Set-Cookie: dsh-auth-…` |
| `DELETE /passkey/keys/{credentialId}` | proxy Basic + DSH cookie | — | `200 {"ok":true}` |

### 2.3 Registration flow

1. Phone is already logged in with the dsh password (proxy Basic + DSH cookie) and
   taps "Register passkey" in Settings.
2. App calls `register/begin`. The gateway mints a random 32-byte challenge, stores
   it for 60 s, and answers with the challenge, a stable user id (derived from the
   dsh username, e.g. SHA-256 of `"dsh"` — the same value on every registration, so
   one user has one passkey identity), `rpId: wuh30617.dpdns.org`, and the ids of
   keys already registered (so the authenticator refuses to make a duplicate).
3. The phone runs the platform ceremony (fingerprint/face, `userVerification:
   required`, `residentKey: required`, `authenticatorAttachment: platform`). The
   private key is created inside the authenticator and never leaves the phone.
4. App posts the attestation to `register/finish`. The gateway verifies, in order:
   the challenge matches a live one and has not been used; `clientDataJSON.type` is
   `webauthn.create`; `origin` is exactly `https://wuh30617.dpdns.org`; `rpIdHash`
   matches `wuh30617.dpdns.org`; the attestation statement is `none` (the app asks
   for `attestation: none`, so no attestation certificate chain is checked); the
   credential public key parses as P-256 (alg `-7`) or Ed25519 (`-8`, if the
   authenticator offers it — the app lists `-7` first, `-257` second).
5. On success the gateway stores the public key, deletes the challenge, and answers
   `200`. The app stores the credential id locally. Registration is done.

### 2.4 Login flow

1. Phone taps "Sign in with passkey" (or the connect screen offers it when a
   registration exists and there is no live session).
2. App calls `login/begin`. The gateway mints a challenge and answers with the
   credential ids it knows, so the authenticator offers the right key.
3. The phone runs the ceremony (biometric, `userVerification: required`) and signs.
4. App posts the assertion to `login/finish`. The gateway verifies: the challenge
   is live; `type` is `webauthn.get`; `origin` is exactly
   `https://wuh30617.dpdns.org`; `rpIdHash` matches; the signature verifies against
   the stored public key over `authenticatorData || SHA-256(clientDataJSON)`; the
   `userPresent` and `userVerified` flags are set; `signCount` has not gone
   backwards (then it is stored).
5. On success the gateway **issues the DSH session cookie itself**: it reads the
   current launch token from the dsh-web log (the same source the existing
   `~/bin/dsh-token-refresh.sh` uses), performs `GET /?token=…` against
   `127.0.0.1:3080`, and copies the `Set-Cookie` it receives onto its own response.
   The app stores that cookie in `HarnessSessionStore` exactly like a password
   login's cookie, and from here on the connection is indistinguishable from one
   that started with a password. If the token exchange fails (DSH down, token
   rotated mid-call), the gateway answers `502` and the app says the login failed
   — the passkey itself verified fine, and retrying is safe.

### 2.5 Phone lost / re-register

1. Change the nginx `dsh` password (old password stops working at the door).
2. Delete the lost phone's public key from `passkeys.json` (or call
   `DELETE /passkey/keys/{credentialId}` from a logged-in phone) and restart the
   gateway — or just edit the file; the gateway re-reads it per request, or on
   `SIGHUP` if it caches.
3. Delete the DSH login record (`~/.dsh/.credentials.yaml` entry) and restart
   `dsh-web`, so the old cookie dies — same step as the existing phone-lost
   procedure in the design proposal (§6.4).
4. New phone: dsh-password login → Settings → "Register passkey". No recovery
   words, no second channel: the password login *is* the recovery channel, by
   design. The old phone's private key is gone with the phone, and its public key
   is deleted, so nothing of the lost device can sign in afterwards.

### 2.6 What it needs

- One new systemd service + one JSON file + two nginx locations. No DSH change, no
  DSH restart, no database.
- Dependencies: a WebAuthn verification library for the implementation language —
  e.g. Node.js `@simplewebauthn/server` (the standard choice; its `verifyRegistrationResponse`
  / `verifyAuthenticationResponse` do the checks in §2.3 step 4 / §2.4 step 4), or
  Go `github.com/go-webauthn/webauthn`, or Python `webauthn`. Pick one; do not
  hand-roll signature verification.
- The gateway must read the dsh-web log to find the current launch token. It runs
  as `museops`, which already owns that log — no new privilege needed.
- **Decision needed before building:** confirm the gateway approach (tiny service
  in front of nginx, §1) rather than a DSH plugin; confirm the implementation
  language (Node.js is the natural pick — DSH is Node, and `@simplewebauthn/server`
  is the best-supported verifier); confirm `rpId` is `wuh30617.dpdns.org` (it must
  be the registrable domain the phone actually visits — it is).

## 3. Content decryptor

### 3.1 What it stores

- The content key: 32 random bytes, base64 in `/home/museops/dsh-security/content-key.b64`
  (mode `0600`, owner `museops`). The phone holds the same key in its Keystore.
  The file is created once, at setup, and **never rotated by the gateway**: a fresh
  key would orphan every earlier encrypted message. Rotation, if ever wanted, is a
  deliberate decision with a warning first (see §3.5).
- The key is generated by whoever sets the component up, copied to the phone once
  (over the already-encrypted channel, after a dsh-password login — the re-pair
  endpoint, §3.3), and then the server copy is the reference.

### 3.2 Wire format (fixed by the app)

One line of text, carried in `session/prompt`'s text part unchanged:

```
dsh-enc-v1:{"v":1,"alg":"AES-256-GCM","kid":"<16 hex fingerprint>","iv":"<base64url>","ct":"<base64url>"}
```

- The `dsh-enc-v1:` prefix is the discriminator: the decryptor recognises an
  encrypted payload by it, and plain text never starts with it, so a mixed
  transcript is readable without a per-message flag. The IV is random per message.
  The GCM tag rides inside `ct`: a tampered envelope fails decryption instead of
  yielding wrong text. `kid` is the key fingerprint, so a key mismatch is
  diagnosed rather than silently producing garbage.
- Only message *text* is encrypted. Images and staged file receipts ride the prompt
  unchanged — the decryptor leaves non-text parts alone.

### 3.3 Endpoints (all under `/dsh/content/`, all behind nginx Basic Auth)

| Method & path | Auth | Request | Response |
|---|---|---|---|
| `GET /content/v1/status` | proxy Basic + DSH cookie | — | `{"ready":true}` |
| `POST /content/v1/repair` | proxy Basic + DSH cookie | `{}` | `{"key":"<base64 raw 32 bytes>"}` |

### 3.4 The decrypt-before-DSH / encrypt-before-phone flow

- **Outbound (phone → DSH):** the app encrypts text parts only when its gate is
  open (toggle on *and* the probe in §3.3 succeeded). The gateway, sitting on the
  `/api` path, inspects each `session/prompt` (and `subagents/prompt`) body: any
  text part starting with `dsh-enc-v1:` is decrypted with the server key and
  replaced by its plaintext before the request is forwarded to `127.0.0.1:3080`.
  A part that fails to decrypt (wrong key, tampered tag) is rejected with the
  request — never forwarded as ciphertext, and never forwarded as guessed text.
  Non-envelope parts pass through byte-for-byte.
- **Inbound (DSH → phone):** v1 does **not** re-encrypt replies. DSH stores and
  returns plaintext, and the phone renders it as usual; the app's
  `ContentEncryptionService.maybeDecrypt` is the hook point for the day replies are
  re-encrypted, but that is a later step, not v1. The threat model in the design
  proposal (§6) is "someone who sees the traffic or the stored messages cannot read
  the words" — v1 covers the phone→server direction, which is the direction that
  crosses the public internet carrying fresh task text. DSH's own session logs on
  srv-main remain plaintext, as they are today; encrypting those is a separate,
  larger decision (DSH would have to be taught to read them back).
- **The app's gate is the safety net:** the toggle cannot be switched on until
  `GET /content/v1/status` answers `ready:true`, and the send path re-checks the
  gate on every prompt. A phone against a server without the decryptor behaves
  exactly like today's build: plain text over TLS.

### 3.5 Key backup / re-pairing / loss

- **Re-pairing (main backup):** a new phone logs in with the dsh password, then
  Settings → "Re-pair key from server". The gateway answers `POST /content/v1/repair`
  with the *same* key it already holds. The phone stores it in its Keystore. The
  fingerprint shown in Settings is how the two copies are checked against each other.
- **Passphrase backup (local backup):** the phone can export the key as one
  passphrase-encrypted line (`dsh-key-backup-v1:…`, PBKDF2-HmacSHA256 120,000
  iterations + AES-256-GCM; see `ContentKeyBackup.kt`). The server never sees this
  line. Restoring it replaces the phone's key with the backed-up one.
- **Optional recovery words:** not implemented in v1. If wanted later, they are a
  second encoding of the same 32 bytes (BIP39 wordlist over the key entropy),
  issued at setup and recoverable without the server. The passphrase backup covers
  the same need with less new code, so v1 ships that instead.
- **Key loss, stated plainly:** lose the phone key, the backup line, *and* the
  server copy, and the encrypted messages cannot be read by anyone — including
  their owner. There is no reset, no master key, and no "forgot key" flow; that is
  the price of the encryption, and the design proposal says so (§6.2/§6.3).
- **Rotation:** not offered as a button. Rotating the key orphans every earlier
  encrypted message, so it needs a warning and a deliberate decision first. If
  rotation is ever wanted, the server generates the new key, the phone re-pairs,
  and the old key is kept read-only for decrypting history — that is a design
  change, not a toggle.

### 3.6 What it needs

- The same gateway process as §2 (one service, two jobs) + the key file + the two
  nginx locations. The `/api` interception is the one part that touches the live
  path: it must be a transparent proxy that forwards everything it does not
  recognise, byte-for-byte, so a decryptor bug can break the chat. Mitigation:
  ship it with the interception **off** behind a flag, verify the passkey half
  first (which touches nothing live), then enable interception and test with one
  encrypted prompt while the model is still out of money — the prompt path up to
  DSH's acceptance is testable without a model reply.
- **Decision needed before building:** confirm the interception point (nginx hop
  in front of `/api`, §1) and confirm v1 does not re-encrypt replies (§3.4);
  confirm the key is generated once at setup and the phone is paired from it
  (rather than the phone generating the key and uploading it — either works, but
  one direction must be chosen; server-generates is recommended, because the
  server copy then exists from the start and re-pairing needs no upload step).

## 4. Verification plan (no model replies needed until the end)

1. `GET /dsh/passkey/status` → `{"installed":true}`; `GET /dsh/content/v1/status` →
   `{"ready":true}`. The app's Settings card stops showing "not installed".
2. Register a passkey from the phone (fingerprint prompt appears, registration
   succeeds, the public key lands in `passkeys.json`).
3. Disconnect, then "Sign in with passkey" → the app connects and the session
   list loads. Wrong-origin check: the same ceremony against any other origin must
   fail — the rpId binding is the test.
4. Revoke the key from the phone; login with it fails; re-register works.
5. Enable content encryption (toggle becomes available), send a prompt: the
   gateway log shows an envelope arriving and plaintext leaving for DSH. (DSH will
   answer 402 for the model call until DeepSeek is topped up — that is expected,
   and the prompt's acceptance, not the reply, is the check.)
6. Phone-lost drill: delete the key server-side, change the nginx password, restart
   `dsh-web`; the old phone cannot get in; a new login + re-register + re-pair
   restores everything.

## 5. Decisions pending (owner: 主人)

1. Gateway approach (§1) over a DSH plugin — approve, and pick the implementation
   language (recommended: Node.js + `@simplewebauthn/server`).
2. `rpId` = `wuh30617.dpdns.org` — confirm.
3. `/api` interception point for the decryptor (§3.4) — approve, and confirm v1
   does not re-encrypt replies.
4. Key generation direction: server generates the content key at setup; the phone
   pairs from it (§3.6).
5. Recovery words: v1 ships the passphrase backup only; recovery words stay
   optional for later — confirm, or ask for them now.
6. When to build: the app side is done and gated; the server side is a fresh build
   on srv-main (new systemd service + nginx locations, no DSH change, no DSH
   restart). It needs a window where a mistake cannot lock the phone out — the
   password login always stays available as the fallback, so the risk is a broken
   *additional* path, not a lockout.
