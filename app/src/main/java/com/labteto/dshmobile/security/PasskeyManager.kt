package com.labteto.dshmobile.security

import android.app.Activity
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialException
import com.labteto.dshmobile.connection.ConnectionManager
import com.labteto.dshmobile.connection.HarnessSessionStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.combine
import javax.inject.Inject
import javax.inject.Singleton

/** What the Settings passkey card shows, and what the register / login buttons may do. */
data class PasskeyUiState(
    /** A passkey is registered on this phone for the active host. */
    val registered: PasskeyRegistration? = null,
    /** Whether the server component answered the probe. Null while never probed. */
    val serverInstalled: Boolean? = null,
    /** Whether the app is connected to a host right now (register / login need one). */
    val connected: Boolean = false,
    /** A register or login ceremony is running. */
    val busy: Boolean = false,
)

/** One register or login attempt, end to end. */
sealed interface PasskeyOutcome {
    data object Registered : PasskeyOutcome
    data object LoggedIn : PasskeyOutcome
    data object Removed : PasskeyOutcome
    /** The user backed out of the fingerprint prompt. Not an error; nothing changed. */
    data object Cancelled : PasskeyOutcome
    /** The server component is not installed, so the ceremony cannot even start. */
    data object ServerMissing : PasskeyOutcome
    /** No host is connected, so there is nowhere to register against or log in to. */
    data object NoHost : PasskeyOutcome
    /** A passkey is already registered for this host; remove it first to register another. */
    data object AlreadyRegistered : PasskeyOutcome
    data class Failed(val message: String) : PasskeyOutcome
}

/**
 * Passkey registration and login, on top of Android Credential Manager.
 *
 * The private key never enters this class: `createCredential` and `getCredential` run the
 * platform ceremony — fingerprint or face, then the authenticator signs — and hand back only
 * the attestation / assertion JSON. This class builds the WebAuthn request JSON from the
 * server's challenge, parses the response, and lets [PasskeyGateway] carry it to the server.
 *
 * The flow is deliberately an *additional* path, never a replacement: first use is always the
 * dsh-password login (which is also what registration requires — the begin call carries the
 * session cookie), and the password + token login keeps working with or without a passkey,
 * and with or without the server component. If the component is not installed, registration
 * and passkey login report [PasskeyOutcome.ServerMissing] and change nothing.
 *
 * `userVerification = "required"` in both request builders is the fingerprint step: the
 * authenticator will not sign without a biometric (or the device credential) first.
 */
@Singleton
class PasskeyManager @Inject constructor(
    private val store: PasskeyStore,
    private val gateway: PasskeyGateway,
    private val connectionManager: ConnectionManager,
    private val sessionStore: HarnessSessionStore,
) {
    private val _serverInstalled = MutableStateFlow<Boolean?>(null)
    private val _busy = MutableStateFlow(false)

    /** Live status for the Settings card, for the host the app is connected to right now. */
    val status: Flow<PasskeyUiState> = combine(
        connectionManager.state,
        _serverInstalled,
        _busy,
    ) { connection, installed, busy ->
        val host = connection.host
        val registration = host?.let { store.registrationOnce(it.id) }
        PasskeyUiState(
            registered = registration,
            serverInstalled = installed,
            connected = host != null,
            busy = busy,
        )
    }

    /** Ask the server component whether it is installed, for the active host. Null when not connected. */
    suspend fun probeServer(): Boolean? {
        val host = connectionManager.state.value.host ?: return null
        val installed = when (val r = gateway.probePasskey(host.baseUrl, host.id)) {
            is GatewayResult.Ok -> r.value
            else -> false
        }
        _serverInstalled.value = installed
        return installed
    }

    /**
     * Register a passkey for the active host, after a dsh-password login.
     *
     * The phone generates the key inside the authenticator; the server keeps only the public
     * key, bound to the relying-party id. [userName] is the display name shown in the
     * authenticator's account picker — the dsh username is the honest value.
     */
    suspend fun register(activity: Activity, userName: String): PasskeyOutcome {
        val host = connectionManager.state.value.host ?: return PasskeyOutcome.NoHost
        if (store.registrationOnce(host.id) != null) return PasskeyOutcome.AlreadyRegistered
        _busy.value = true
        try {
            val begin = when (val r = gateway.beginRegister(host.baseUrl, host.id)) {
                is GatewayResult.Ok -> r.value
                is GatewayResult.ServerMissing -> return PasskeyOutcome.ServerMissing.also { _serverInstalled.value = false }
                is GatewayResult.Failed -> return PasskeyOutcome.Failed(r.message)
            }
            val requestJson = buildCreateRequestJson(
                rpId = begin.rpId,
                rpName = "DSH (${host.authority})",
                userIdBase64Url = begin.userIdBase64Url,
                userName = userName,
                userDisplayName = userName,
                challengeBase64Url = begin.challengeBase64Url,
                excludeCredentialIds = begin.excludeCredentialIds,
            )
            val manager = CredentialManager.create(activity)
            val response = try {
                manager.createCredential(CreatePublicKeyCredentialRequest(requestJson), activity)
            } catch (e: CreateCredentialCancellationException) {
                return PasskeyOutcome.Cancelled
            } catch (e: CreateCredentialException) {
                return PasskeyOutcome.Failed(e.message ?: "passkey registration failed")
            }
            val credential = response.data as? PublicKeyCredential
                ?: return PasskeyOutcome.Failed("authenticator did not return a passkey credential")
            val attestation = parseCreateResponseJson(credential.registrationResponseJson)
                ?: return PasskeyOutcome.Failed("authenticator answer was not a passkey attestation")
            when (val finished = gateway.finishRegister(host.baseUrl, host.id, attestation)) {
                is GatewayResult.Ok -> Unit
                is GatewayResult.ServerMissing -> return PasskeyOutcome.ServerMissing
                is GatewayResult.Failed -> return PasskeyOutcome.Failed(finished.message)
            }
            store.save(
                host.id,
                PasskeyRegistration(
                    credentialId = attestation.rawIdBase64Url,
                    rpId = begin.rpId,
                    createdAt = System.currentTimeMillis(),
                ),
            )
            return PasskeyOutcome.Registered
        } finally {
            _busy.value = false
        }
    }

    /**
     * Log in with the passkey for the active host.
     *
     * The authenticator signs the server's challenge after a biometric; the gateway verifies
     * the signature against the stored public key and answers with the DSH session cookie,
     * which is stored exactly like a password login's cookie. The app then connects as usual —
     * from here on nothing distinguishes this session from one that started with a password.
     */
    suspend fun login(activity: Activity): PasskeyOutcome {
        val host = connectionManager.state.value.host ?: return PasskeyOutcome.NoHost
        _busy.value = true
        try {
            val begin = when (val r = gateway.beginLogin(host.baseUrl, host.id)) {
                is GatewayResult.Ok -> r.value
                is GatewayResult.ServerMissing -> return PasskeyOutcome.ServerMissing.also { _serverInstalled.value = false }
                is GatewayResult.Failed -> return PasskeyOutcome.Failed(r.message)
            }
            val requestJson = buildGetRequestJson(
                rpId = begin.rpId,
                challengeBase64Url = begin.challengeBase64Url,
                allowCredentialIds = begin.allowCredentialIds,
            )
            val manager = CredentialManager.create(activity)
            val response = try {
                manager.getCredential(
                    GetCredentialRequest(listOf(GetPublicKeyCredentialOption(requestJson))),
                    activity,
                )
            } catch (e: GetCredentialCancellationException) {
                return PasskeyOutcome.Cancelled
            } catch (e: GetCredentialException) {
                return PasskeyOutcome.Failed(e.message ?: "passkey sign-in failed")
            }
            val credential = response.credential as? PublicKeyCredential
                ?: return PasskeyOutcome.Failed("authenticator did not return a passkey credential")
            val assertion = parseGetResponseJson(credential.authenticationResponseJson)
                ?: return PasskeyOutcome.Failed("authenticator answer was not a passkey assertion")
            val cookie = when (val finished = gateway.finishLogin(host.baseUrl, host.id, assertion)) {
                is GatewayResult.Ok -> finished.value
                is GatewayResult.ServerMissing -> return PasskeyOutcome.ServerMissing
                is GatewayResult.Failed -> return PasskeyOutcome.Failed(finished.message)
            }
            sessionStore.remember(host.id, cookie)
            return PasskeyOutcome.LoggedIn
        } finally {
            _busy.value = false
        }
    }

    /**
     * Remove the passkey for the active host.
     *
     * The local record is always dropped. The server-side revocation is best-effort: a
     * failure there does not block the removal, because the private key stays on this phone
     * and the server record alone cannot sign anything — and the phone-lost procedure clears
     * the server record on the machine itself.
     */
    suspend fun remove(): PasskeyOutcome {
        val host = connectionManager.state.value.host ?: return PasskeyOutcome.NoHost
        val registration = store.registrationOnce(host.id) ?: return PasskeyOutcome.Removed
        runCatching { gateway.revokeKey(host.baseUrl, host.id, registration.credentialId) }
        store.remove(host.id)
        return PasskeyOutcome.Removed
    }
}
