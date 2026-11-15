package com.labteto.dshmobile.security

import com.labteto.dshmobile.core.wire.WireJson
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

/**
 * What a call to the passkey / content server component came back as.
 *
 * [ServerMissing] is the honest answer while the component is not installed: the gateway
 * answers 404 on every one of these paths, and the app must say so rather than report a
 * login failure. Nothing here retries — a 404 today means "not installed", and asking again
 * with the same request produces the same answer until someone installs the component.
 */
sealed interface GatewayResult<out T> {
    data class Ok<T>(val value: T) : GatewayResult<T>
    /** The path answered 404: the server component is not installed (yet). */
    data class ServerMissing(val status: Int = 404) : GatewayResult<Nothing>
    /** The server answered, or the network failed, with something that is not a success. */
    data class Failed(val message: String) : GatewayResult<Nothing>
}

/**
 * The HTTP side of the passkey and content-encryption server components, built by the
 * [com.labteto.dshmobile.di.AppModule] provider — the credential lookups arrive as lambdas
 * so a unit test can hand over fixed values instead of a DataStore, while the app binds
 * them to the proxy credential store and the harness session store.
 *
 * Every call goes to `{baseUrl}passkey/...` or `{baseUrl}content/...` under the harness's own
 * subpath (`https://wuh30617.dpdns.org/dsh/`), behind the same nginx Basic auth as everything
 * else — so each request carries the proxy `Authorization` header, exactly like the token
 * exchange and the `/api` calls. Registration and re-pairing additionally carry the DSH
 * session cookie: only a phone that already logged in with the dsh password may register a
 * passkey or ask for the content key back, which is what makes "phone lost → re-register
 * with the dsh password" work without a second enrolment channel.
 *
 * The endpoints do not exist yet — see `docs/dsh-mobile-passkey-and-encryption-server.md`
 * for the component that has to be built first. Until it exists every call lands here as
 * [GatewayResult.ServerMissing], and the app keeps working on the password + token path.
 */
class PasskeyGateway(
    private val http: OkHttpClient,
    private val proxyAuthorization: suspend (String) -> String?,
    private val sessionCookie: suspend (String) -> String?,
) {
    /** `GET {baseUrl}passkey/status` — 200 with `{"installed":true}` when the component is there. */
    suspend fun probePasskey(baseUrl: String, hostId: String): GatewayResult<Boolean> {
        val result = get("$baseUrl/passkey/status", hostId, withCookie = false)
        return when (result) {
            is GatewayResult.Ok -> {
                val installed = runCatching {
                    WireJson.parseToJsonElement(result.value).jsonObject["installed"]?.jsonPrimitive?.content == "true"
                }.getOrDefault(false)
                GatewayResult.Ok(installed)
            }
            is GatewayResult.ServerMissing -> GatewayResult.Ok(false)
            is GatewayResult.Failed -> result
        }
    }

    /** `POST {baseUrl}passkey/register/begin` — the challenge registration signs over. */
    suspend fun beginRegister(baseUrl: String, hostId: String): GatewayResult<RegisterBegin> {
        val result = post("$baseUrl/passkey/register/begin", hostId, "{}")
        return when (result) {
            is GatewayResult.Ok -> parseRegisterBegin(result.value)?.let { GatewayResult.Ok(it) }
                ?: GatewayResult.Failed("register/begin answer was not a challenge")
            is GatewayResult.ServerMissing -> result
            is GatewayResult.Failed -> result
        }
    }

    /** `POST {baseUrl}passkey/register/finish` — the attestation, for the server to verify and store. */
    suspend fun finishRegister(baseUrl: String, hostId: String, attestation: PasskeyAttestation): GatewayResult<Unit> {
        val body = WireJson.encodeToString(
            JsonObject.serializer(),
            buildJsonObject {
                put("id", attestation.id)
                put("rawId", attestation.rawIdBase64Url)
                put("attestationObject", attestation.attestationObjectBase64Url)
                put("clientDataJSON", attestation.clientDataJsonBase64Url)
            },
        )
        return when (val result = post("$baseUrl/passkey/register/finish", hostId, body)) {
            is GatewayResult.Ok -> GatewayResult.Ok(Unit)
            is GatewayResult.ServerMissing -> result
            is GatewayResult.Failed -> result
        }
    }

    /** `POST {baseUrl}passkey/login/begin` — the challenge login signs over. */
    suspend fun beginLogin(baseUrl: String, hostId: String): GatewayResult<LoginBegin> {
        val result = post("$baseUrl/passkey/login/begin", hostId, "{}", withCookie = false)
        return when (result) {
            is GatewayResult.Ok -> parseLoginBegin(result.value)?.let { GatewayResult.Ok(it) }
                ?: GatewayResult.Failed("login/begin answer was not a challenge")
            is GatewayResult.ServerMissing -> result
            is GatewayResult.Failed -> result
        }
    }

    /**
     * `POST {baseUrl}passkey/login/finish` — the assertion, for the server to verify.
     *
     * On success the gateway answers with the DSH session cookie in `Set-Cookie`, exactly as
     * the launch-token exchange does: the gateway reads the current launch token from the
     * dsh-web log on the machine, exchanges it for a cookie, and hands that cookie to the
     * phone. The app stores it in [HarnessSessionStore] the same way, so from here on the
     * connection is indistinguishable from a password login.
     */
    suspend fun finishLogin(baseUrl: String, hostId: String, assertion: PasskeyAssertion): GatewayResult<String> {
        val body = WireJson.encodeToString(
            JsonObject.serializer(),
            buildJsonObject {
                put("id", assertion.id)
                put("rawId", assertion.rawIdBase64Url)
                put("authenticatorData", assertion.authenticatorDataBase64Url)
                put("clientDataJSON", assertion.clientDataJsonBase64Url)
                put("signature", assertion.signatureBase64Url)
                assertion.userHandleBase64Url?.let { put("userHandle", it) }
            },
        )
        val request = buildRequest("$baseUrl/passkey/login/finish", hostId, body, withCookie = false)
            ?: return GatewayResult.Failed("no host")
        return runCatching {
            withContext(Dispatchers.IO) {
                http.newCall(request).execute().use { response ->
                    when {
                        response.code == 404 -> GatewayResult.ServerMissing(404)
                        !response.isSuccessful -> GatewayResult.Failed("login/finish refused: HTTP ${response.code}")
                        else -> {
                            val cookie = response.headers("Set-Cookie")
                                .firstOrNull { it.startsWith("dsh-auth-") }
                                ?.substringBefore(";")
                            if (cookie != null) GatewayResult.Ok(cookie)
                            else GatewayResult.Failed("login/finish verified but issued no session cookie")
                        }
                    }
                }
            }
        }.getOrElse { GatewayResult.Failed(it.message ?: "login/finish failed") }
    }

    /**
     * `DELETE {baseUrl}passkey/keys/{credentialId}` — best-effort revocation of one key.
     *
     * Removing a passkey from the phone always drops the local record; this call is the
     * server-side half, and a failure here does not block the local removal — the key is
     * useless without the phone that holds its private half, and the server record can be
     * cleared on the machine itself (see the phone-lost procedure in the design doc).
     */
    suspend fun revokeKey(baseUrl: String, hostId: String, credentialId: String): Boolean {
        val request = buildRequest("$baseUrl/passkey/keys/$credentialId", hostId, body = null, withCookie = true, delete = true)
            ?: return false
        return runCatching {
            withContext(Dispatchers.IO) { http.newCall(request).execute().use { it.isSuccessful } }
        }.getOrDefault(false)
    }

    /**
     * `GET {baseUrl}content/v1/status` — 200 with `{"ready":true}` when the decryptor is there.
     *
     * The content-encryption toggle is gated on this answer: turning encryption on without
     * the decryptor would send DSH ciphertext it cannot read, so the app refuses to enable
     * it until this probe succeeds.
     */
    suspend fun probeDecryptor(baseUrl: String, hostId: String): GatewayResult<Boolean> {
        val result = get("$baseUrl/content/v1/status", hostId, withCookie = true)
        return when (result) {
            is GatewayResult.Ok -> {
                val ready = runCatching {
                    WireJson.parseToJsonElement(result.value).jsonObject["ready"]?.jsonPrimitive?.content == "true"
                }.getOrDefault(false)
                GatewayResult.Ok(ready)
            }
            is GatewayResult.ServerMissing -> GatewayResult.Ok(false)
            is GatewayResult.Failed -> result
        }
    }

    /**
     * `POST {baseUrl}content/v1/repair` — re-issue the content key to a new phone.
     *
     * Only after a dsh-password login (proxy Basic + DSH cookie both travel), and only the
     * same key the server already holds — never a fresh one, or every earlier encrypted
     * message would stop decrypting. Answers `{"key":"<base64 raw 32 bytes>"}`.
     */
    suspend fun repairKey(baseUrl: String, hostId: String): GatewayResult<ByteArray> {
        val result = post("$baseUrl/content/v1/repair", hostId, "{}")
        return when (result) {
            is GatewayResult.Ok -> runCatching {
                val encoded = WireJson.parseToJsonElement(result.value).jsonObject["key"]?.jsonPrimitive?.content
                    ?: return GatewayResult.Failed("repair answer carried no key")
                GatewayResult.Ok(java.util.Base64.getDecoder().decode(encoded))
            }.getOrElse { GatewayResult.Failed("repair answer was not a key") }
            is GatewayResult.ServerMissing -> result
            is GatewayResult.Failed -> result
        }
    }

    private suspend fun get(url: String, hostId: String, withCookie: Boolean): GatewayResult<String> {
        val request = buildRequest(url, hostId, body = null, withCookie = withCookie) ?: return GatewayResult.Failed("no host")
        return execute(request)
    }

    private suspend fun post(url: String, hostId: String, body: String, withCookie: Boolean = true): GatewayResult<String> {
        val request = buildRequest(url, hostId, body, withCookie = withCookie) ?: return GatewayResult.Failed("no host")
        return execute(request)
    }

    private suspend fun execute(request: Request): GatewayResult<String> = runCatching {
        withContext(Dispatchers.IO) {
            http.newCall(request).execute().use { response ->
                when {
                    response.code == 404 -> GatewayResult.ServerMissing(404)
                    !response.isSuccessful -> GatewayResult.Failed("HTTP ${response.code}")
                    else -> GatewayResult.Ok(response.body?.string().orEmpty())
                }
            }
        }
    }.getOrElse { GatewayResult.Failed(it.message ?: "request failed") }

    private suspend fun buildRequest(
        url: String,
        hostId: String,
        body: String?,
        withCookie: Boolean,
        delete: Boolean = false,
    ): Request? {
        // `baseUrl` may or may not end in a slash, and every endpoint path is written with a
        // leading one, so collapse doubled slashes once here instead of trusting every call
        // site. The lookbehind keeps the `://` of the scheme intact.
        val clean = url.replace(Regex("(?<!:)/{2,}"), "/")
        val builder = Request.Builder().url(clean)
        proxyAuthorization(hostId)?.let { builder.header("Authorization", it) }
        if (withCookie) {
            sessionCookie(hostId)?.let { builder.header("Cookie", it) }
        }
        when {
            delete -> builder.delete()
            body != null -> builder.post(body.toRequestBody(JSON))
            else -> builder.get()
        }
        return builder.build()
    }

    private companion object {
        val JSON = "application/json; charset=utf-8".toMediaType()
    }
}
