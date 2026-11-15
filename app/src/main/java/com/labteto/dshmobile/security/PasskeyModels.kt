package com.labteto.dshmobile.security

import com.labteto.dshmobile.core.wire.WireJson
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import java.util.Base64

/**
 * One passkey registered on this phone, for one harness host.
 *
 * Only the public half of the credential is ever stored or sent anywhere: the credential id, the
 * relying-party id it is bound to, and the user handle. The private key itself lives inside the
 * platform authenticator (Android Credential Manager / Play Services FIDO2) and is never visible
 * to this app at all — registration hands the app an attestation, and signing hands it an
 * assertion. Losing this record only loses the *pointer* to the key; the key itself is removed
 * from the authenticator by removing the credential there, which the Settings "remove passkey"
 * action does through the server-side revocation plus dropping this record.
 *
 * The record is per host id, matching [com.labteto.dshmobile.connection.ProxyCredentialStore]:
 * one harness, one passkey. A passkey is bound to its relying party id
 * (`wuh30617.dpdns.org` for the srv-main gateway), so a credential registered for one host
 * cannot be replayed at another origin — that binding is what makes it phishing-resistant,
 * and it is also why the record keeps the rpId it was made for.
 */
@Serializable
data class PasskeyRegistration(
    /** Base64url credential id, as the authenticator returned it. */
    val credentialId: String,
    /** The relying-party id the key is bound to, e.g. `wuh30617.dpdns.org`. */
    val rpId: String,
    /** Base64url user handle, when the authenticator supplied one. */
    val userHandle: String? = null,
    /** Epoch millis the registration finished. */
    val createdAt: Long = 0L,
)

/** Base64url without padding, the encoding WebAuthn uses everywhere. */
fun ByteArray.toBase64Url(): String = Base64.getUrlEncoder().withoutPadding().encodeToString(this)

/** Decode base64url, tolerating missing padding. */
fun String.base64UrlToBytes(): ByteArray {
    val padded = this + "=".repeat((4 - length % 4) % 4)
    return Base64.getUrlDecoder().decode(padded)
}

/**
 * The `PublicKeyCredentialCreationOptions` JSON handed to Credential Manager for registration.
 *
 * Built here, not on the server, only in the sense that the *shape* is fixed: the challenge,
 * the user id and the exclusion list come from the server's register/begin answer, and this
 * function only lays them out in the form `CreatePublicKeyCredentialRequest` wants. A server
 * that speaks the documented contract can equally hand the whole JSON over itself; the app
 * accepts either, but the begin answer is the narrow part — challenge, user id, exclusions —
 * so the app builds the request around it.
 */
fun buildCreateRequestJson(
    rpId: String,
    rpName: String,
    userIdBase64Url: String,
    userName: String,
    userDisplayName: String,
    challengeBase64Url: String,
    excludeCredentialIds: List<String>,
): String = WireJson.encodeToString(
    JsonObject.serializer(),
    buildJsonObject {
        putJsonObject("rp") {
            put("id", rpId)
            put("name", rpName)
        }
        putJsonObject("user") {
            put("id", userIdBase64Url)
            put("name", userName)
            put("displayName", userDisplayName)
        }
        put("challenge", challengeBase64Url)
        putJsonArray("pubKeyCredParams") {
            addJsonObject { put("type", "public-key"); put("alg", -7) }
            addJsonObject { put("type", "public-key"); put("alg", -257) }
        }
        put("timeout", 60_000)
        putJsonObject("authenticatorSelection") {
            put("authenticatorAttachment", "platform")
            put("residentKey", "required")
            put("userVerification", "required")
        }
        put("attestation", "none")
        if (excludeCredentialIds.isNotEmpty()) {
            putJsonArray("excludeCredentials") {
                excludeCredentialIds.forEach { id ->
                    addJsonObject {
                        put("type", "public-key")
                        put("id", id)
                        putJsonArray("transports") { add(JsonPrimitive("internal")) }
                    }
                }
            }
        }
    },
)

/** The `PublicKeyCredentialRequestOptions` JSON handed to Credential Manager for login. */
fun buildGetRequestJson(
    rpId: String,
    challengeBase64Url: String,
    allowCredentialIds: List<String>,
): String = WireJson.encodeToString(
    JsonObject.serializer(),
    buildJsonObject {
        put("challenge", challengeBase64Url)
        put("rpId", rpId)
        put("timeout", 60_000)
        put("userVerification", "required")
        if (allowCredentialIds.isNotEmpty()) {
            putJsonArray("allowCredentials") {
                allowCredentialIds.forEach { id ->
                    addJsonObject {
                        put("type", "public-key")
                        put("id", id)
                        putJsonArray("transports") { add(JsonPrimitive("internal")) }
                    }
                }
            }
        }
    },
)

/** What the authenticator returns from a registration ceremony, before it goes to the server. */
data class PasskeyAttestation(
    val id: String,
    val rawIdBase64Url: String,
    val attestationObjectBase64Url: String,
    val clientDataJsonBase64Url: String,
)

/**
 * Parse the `registrationResponseJson` Credential Manager hands back.
 *
 * The fields are already base64url in that JSON; this only pulls them out and checks the shape.
 * A response that is not a `public-key` credential, or that lacks any of the three fields the
 * server must verify, is rejected here rather than sent on to fail server-side.
 */
fun parseCreateResponseJson(responseJson: String): PasskeyAttestation? {
    val root = runCatching { WireJson.parseToJsonElement(responseJson).jsonObject }.getOrNull() ?: return null
    if (root["type"]?.jsonPrimitive?.content != "public-key") return null
    val response = root["response"]?.jsonObject ?: return null
    val rawId = root["rawId"]?.jsonPrimitive?.content ?: return null
    val attestation = response["attestationObject"]?.jsonPrimitive?.content ?: return null
    val clientData = response["clientDataJSON"]?.jsonPrimitive?.content ?: return null
    return PasskeyAttestation(
        id = root["id"]?.jsonPrimitive?.content ?: rawId,
        rawIdBase64Url = rawId,
        attestationObjectBase64Url = attestation,
        clientDataJsonBase64Url = clientData,
    )
}

/** What the authenticator returns from a login ceremony, before it goes to the server. */
data class PasskeyAssertion(
    val id: String,
    val rawIdBase64Url: String,
    val authenticatorDataBase64Url: String,
    val clientDataJsonBase64Url: String,
    val signatureBase64Url: String,
    val userHandleBase64Url: String? = null,
)

/** Parse the `authenticationResponseJson` Credential Manager hands back; same strictness as [parseCreateResponseJson]. */
fun parseGetResponseJson(responseJson: String): PasskeyAssertion? {
    val root = runCatching { WireJson.parseToJsonElement(responseJson).jsonObject }.getOrNull() ?: return null
    if (root["type"]?.jsonPrimitive?.content != "public-key") return null
    val response = root["response"]?.jsonObject ?: return null
    val rawId = root["rawId"]?.jsonPrimitive?.content ?: return null
    val authenticatorData = response["authenticatorData"]?.jsonPrimitive?.content ?: return null
    val clientData = response["clientDataJSON"]?.jsonPrimitive?.content ?: return null
    val signature = response["signature"]?.jsonPrimitive?.content ?: return null
    return PasskeyAssertion(
        id = root["id"]?.jsonPrimitive?.content ?: rawId,
        rawIdBase64Url = rawId,
        authenticatorDataBase64Url = authenticatorData,
        clientDataJsonBase64Url = clientData,
        signatureBase64Url = signature,
        userHandleBase64Url = response["userHandle"]?.jsonPrimitive?.content,
    )
}

/** The server's answer to register/begin: the challenge the authenticator must sign over. */
data class RegisterBegin(
    val challengeBase64Url: String,
    val userIdBase64Url: String,
    val userName: String,
    val rpId: String,
    val excludeCredentialIds: List<String> = emptyList(),
)

/** The server's answer to login/begin. */
data class LoginBegin(
    val challengeBase64Url: String,
    val rpId: String,
    val allowCredentialIds: List<String> = emptyList(),
)

internal fun parseRegisterBegin(json: String): RegisterBegin? {
    val root = runCatching { WireJson.parseToJsonElement(json).jsonObject }.getOrNull() ?: return null
    val challenge = root["challenge"]?.jsonPrimitive?.content ?: return null
    val userId = root["userId"]?.jsonPrimitive?.content ?: return null
    val userName = root["userName"]?.jsonPrimitive?.content ?: return null
    val rpId = root["rpId"]?.jsonPrimitive?.content ?: return null
    val excluded = root["excludeCredentials"]?.jsonArray?.mapNotNull {
        it.jsonObject["id"]?.jsonPrimitive?.content
    }.orEmpty()
    return RegisterBegin(challenge, userId, userName, rpId, excluded)
}

internal fun parseLoginBegin(json: String): LoginBegin? {
    val root = runCatching { WireJson.parseToJsonElement(json).jsonObject }.getOrNull() ?: return null
    val challenge = root["challenge"]?.jsonPrimitive?.content ?: return null
    val rpId = root["rpId"]?.jsonPrimitive?.content ?: return null
    val allowed = root["allowCredentials"]?.jsonArray?.mapNotNull {
        it.jsonObject["id"]?.jsonPrimitive?.content
    }.orEmpty()
    return LoginBegin(challenge, rpId, allowed)
}
