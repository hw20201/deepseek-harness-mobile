package com.labteto.dshmobile.ui.screens.settings

import android.app.Activity
import android.content.Intent
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.labteto.dshmobile.connection.AppSettings
import com.labteto.dshmobile.security.BackupImportResult
import com.labteto.dshmobile.security.ContentEncryptionService
import com.labteto.dshmobile.security.ContentEncryptionState
import com.labteto.dshmobile.security.PasskeyManager
import com.labteto.dshmobile.security.PasskeyOutcome
import com.labteto.dshmobile.security.PasskeyStore
import com.labteto.dshmobile.security.PasskeyUiState
import com.labteto.dshmobile.security.RepairOutcome
import com.labteto.dshmobile.connection.ConnectionManager
import com.labteto.dshmobile.connection.ConnectionUiState
import com.labteto.dshmobile.connection.DiscoveryEngine
import com.labteto.dshmobile.connection.HostsStore
import com.labteto.dshmobile.connection.ProbeOutcome
import com.labteto.dshmobile.connection.ProbeTimeouts
import com.labteto.dshmobile.connection.ProxyCredentialStore
import com.labteto.dshmobile.connection.RelayCredentialStore
import com.labteto.dshmobile.data.SessionStore
import com.labteto.dshmobile.providers.DiscoverOutcome
import com.labteto.dshmobile.providers.ModelProviderManager
import com.labteto.dshmobile.providers.ProviderModelDraft
import com.labteto.dshmobile.providers.ProviderOutcome
import com.labteto.dshmobile.providers.ProviderRow
import com.labteto.dshmobile.providers.ProvidersUiState
import com.labteto.dshmobile.update.UpdateChecker
import com.labteto.dshmobile.termux.HarnessControl
import com.labteto.dshmobile.termux.TermuxHarnessController
import com.labteto.dshmobile.ui.screens.connect.LoopbackStatus
import com.labteto.dshmobile.ui.screens.connect.toLoopbackStatus
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * App-language choices: the 11 shipped locales, plus following the system.
 *
 * A null [tag] clears the override. Without it the picker is a one-way door — once a language is
 * chosen there is no way back to whatever the device is set to.
 */
data class LanguageOption(val tag: String?, val label: String?, val labelRes: Int? = null)

val LanguageOptions = listOf(
    LanguageOption(null, null, com.labteto.dshmobile.R.string.settings_language_system),
    LanguageOption("en", "English"),
    LanguageOption("zh", "中文"),
    LanguageOption("hi", "हिन्दी"),
    LanguageOption("es", "Español"),
    LanguageOption("fr", "Français"),
    LanguageOption("ar", "العربية"),
    LanguageOption("bn", "বাংলা"),
    LanguageOption("pt", "Português"),
    LanguageOption("ru", "Русский"),
    LanguageOption("ur", "اردو"),
    LanguageOption("th", "ไทย"),
)

@HiltViewModel
class SettingsViewModel @Inject constructor(
    private val hostsStore: HostsStore,
    private val credentials: RelayCredentialStore,
    private val proxyCredentials: ProxyCredentialStore,
    private val connectionManager: ConnectionManager,
    private val updateChecker: UpdateChecker,
    private val termux: TermuxHarnessController,
    private val discoveryEngine: DiscoveryEngine,
    private val passkeyManager: PasskeyManager,
    private val passkeyStore: PasskeyStore,
    private val contentEncryption: ContentEncryptionService,
    private val modelProviders: ModelProviderManager,
    private val sessionStore: SessionStore,
) : ViewModel() {

    /** The manual update check; see [UpdateChecker.checkNow]. */
    suspend fun checkForUpdateNow(currentVersion: String): UpdateChecker.CheckOutcome =
        updateChecker.checkNow(currentVersion)

    private val _state = MutableStateFlow(AppSettings())
    val state: StateFlow<AppSettings> = _state.asStateFlow()

    /** What the Termux controller is doing; the card shows it and re-probes when it settles. */
    val harnessControl: StateFlow<HarnessControl> = termux.state

    val termuxInstalled: Boolean get() = termux.termuxInstalled

    private val _loopback = MutableStateFlow<LoopbackStatus>(LoopbackStatus.Unknown)

    /** What the harness on this device is doing, probed once when the card appears. */
    val loopback: StateFlow<LoopbackStatus> = _loopback.asStateFlow()

    /** The port the "this phone" record uses; 3080 until the connect screen says otherwise. */
    val loopbackPort: StateFlow<Int> = hostsStore.hosts
        .map { hosts -> hosts.firstOrNull { it.isLoopback && !it.isRelay }?.port ?: DEFAULT_PORT }
        .stateIn(viewModelScope, SharingStarted.Eagerly, DEFAULT_PORT)

    /** How many harnesses the phone remembers, so "forget them" can say how many it means. */
    val rememberedHostCount: StateFlow<Int> = hostsStore.hosts
        .map { hosts -> hosts.size }
        .stateIn(viewModelScope, SharingStarted.Eagerly, 0)

    val connectionState: StateFlow<ConnectionUiState> = connectionManager.state.stateIn(
        viewModelScope,
        SharingStarted.Eagerly,
        ConnectionUiState()
    )

    /** Passkey status for the Security card: registration, server component, connection. */
    val passkeyStatus: StateFlow<PasskeyUiState> = passkeyManager.status.stateIn(
        viewModelScope,
        SharingStarted.Eagerly,
        PasskeyUiState(),
    )

    /** Content-encryption state for the Security card: gate, key, fingerprint. */
    val contentEncryptionState: StateFlow<ContentEncryptionState> = contentEncryption.state.stateIn(
        viewModelScope,
        SharingStarted.Eagerly,
        ContentEncryptionState(),
    )

    /** Ask the server component whether its passkey side is installed. Null when not connected. */
    suspend fun probePasskeyServer(): Boolean? = passkeyManager.probeServer()

    /** Register a passkey for the active host, after a dsh-password login. */
    suspend fun registerPasskey(activity: Activity): PasskeyOutcome {
        val userName = connectionManager.state.value.host?.proxyUsername ?: "dsh"
        return passkeyManager.register(activity, userName)
    }

    /** Log in with the passkey for the active host. */
    suspend fun loginWithPasskey(activity: Activity): PasskeyOutcome = passkeyManager.login(activity)

    /** Remove the passkey for the active host (local record always, server revocation best-effort). */
    suspend fun removePasskey(): PasskeyOutcome = passkeyManager.remove()

    /** Make sure a content key exists on this phone, generating it at first setup. */
    suspend fun ensureContentKey() = contentEncryption.ensureKey()

    /** Ask the server component whether its decryptor is installed. Null when not connected. */
    suspend fun probeDecryptor(): Boolean? = contentEncryption.probeDecryptor()

    /**
     * Switch content encryption on or off. Returns false when switching on was refused —
     * the decryptor probe has not succeeded — so the toggle can never break the send path.
     */
    suspend fun setContentEncryption(enabled: Boolean): Boolean = contentEncryption.setEnabled(enabled)

    /** A passphrase-encrypted backup line for the content key. Null when there is no key yet. */
    suspend fun exportContentBackup(passphrase: String): String? = contentEncryption.exportBackup(passphrase)

    /** Restore the content key from a backup line. */
    suspend fun importContentBackup(blob: String, passphrase: String): BackupImportResult =
        contentEncryption.importBackup(blob, passphrase)

    /** Re-pair: ask the server for the content key it already holds, after a dsh-password login. */
    suspend fun repairContentKey(): RepairOutcome = contentEncryption.repairKey()

    /** Model-provider status for the Models card. */
    val providersState: StateFlow<ProvidersUiState> = modelProviders.state

    /** Re-reads the providers and the key state. */
    suspend fun refreshProviders(): ProviderOutcome = modelProviders.refresh()

    /** Asks an endpoint for its model list; the key is for this interrogation alone. */
    suspend fun discoverProviderModels(
        settingsNs: String,
        provider: String?,
        baseUrl: String?,
        api: String?,
        apiKey: String?,
    ): DiscoverOutcome = modelProviders.discover(settingsNs, provider, baseUrl, api, apiKey)

    /**
     * Claims a built-in route. On success the model catalog is re-read, so the new
     * provider's models appear in the picker without reopening the session.
     */
    suspend fun saveClaimedProvider(
        row: ProviderRow,
        api: String,
        baseUrl: String?,
        key: String?,
        models: List<ProviderModelDraft>?,
    ): ProviderOutcome {
        val outcome = modelProviders.saveClaim(row, api, baseUrl, key, models)
        if (outcome is ProviderOutcome.Ok) sessionStore.refreshModels()
        return outcome
    }

    /** Declares a custom route; the catalog is re-read on success, as for a claim. */
    suspend fun saveCustomProvider(
        route: String,
        displayName: String?,
        baseUrl: String,
        api: String,
        models: List<ProviderModelDraft>,
        key: String?,
    ): ProviderOutcome {
        val outcome = modelProviders.saveCustom(route, displayName, baseUrl, api, models, key)
        if (outcome is ProviderOutcome.Ok) sessionStore.refreshModels()
        return outcome
    }

    /** Removes a provider; the catalog is re-read on success, as for a save. */
    suspend fun removeProvider(row: ProviderRow): ProviderOutcome {
        val outcome = modelProviders.remove(row)
        if (outcome is ProviderOutcome.Ok) sessionStore.refreshModels()
        return outcome
    }

    init {
        viewModelScope.launch {
            hostsStore.settings.collect { _state.value = it }
        }
        viewModelScope.launch {
            var previous: HarnessControl = HarnessControl.Idle
            termux.state.collect { control ->
                val settledAfterStop = previous is HarnessControl.Stopping && control is HarnessControl.Idle
                if (control is HarnessControl.Started || settledAfterStop) refreshLoopback()
                previous = control
            }
        }
    }

    /** Probe `127.0.0.1:port` with the cookie this app holds for it, as the connect screen does. */
    fun refreshLoopback() {
        viewModelScope.launch {
            val port = loopbackPort.value
            val known = hostsStore.hosts.first().firstOrNull { it.isLoopback && !it.isRelay && it.port == port }
            _loopback.value = runCatching {
                discoveryEngine.probeOutcome(LOOPBACK, port, ProbeTimeouts.Manual, preflight = true, config = known)
            }.getOrElse { ProbeOutcome.Other(it.message ?: "probe failed") }.toLoopbackStatus()
        }
    }

    fun hasTermuxPermission(): Boolean = termux.hasPermission()

    fun openTermuxIntent(): Intent? = termux.launchTermuxIntent()

    fun startHarness() = termux.start(loopbackPort.value)

    /**
     * Stop the harness on this device, leaving the app disconnected on purpose.
     *
     * Stopping the very host the app is connected to would otherwise leave the manager retrying a
     * socket that is never coming back, with the chat still on screen; disconnecting first puts
     * the connect screen up, where the card says the harness is down.
     */
    fun stopHarness() {
        val active = connectionManager.state.value.host
        if (active != null && active.isLoopback && active.port == loopbackPort.value) {
            connectionManager.disconnect()
        }
        termux.stop(loopbackPort.value)
    }

    fun acknowledgeHarnessControl() = termux.acknowledge()

    fun set(transform: (AppSettings) -> AppSettings) {
        viewModelScope.launch {
            hostsStore.setSetting(transform)
        }
    }

    fun disconnect() {
        connectionManager.disconnect()
    }

    /**
     * Forget every remembered harness; the connect screen starts from discovery again.
     *
     * Relay credentials go with them. `removeHost` already drops each one, and the sweep afterwards
     * catches anything orphaned by an earlier build — a stored bearer token nothing can present any
     * more is only a liability. Revoking the device entry itself happens on the relay, not here.
     */
    fun forgetHosts(onDone: () -> Unit = {}) {
        viewModelScope.launch {
            hostsStore.hosts.first().forEach { hostsStore.removeHost(it.id) }
            credentials.clear()
            // A passkey is bound to a host this phone no longer remembers; the server record
            // stays (it is useless without this phone's private key) and is cleared on the
            // machine itself by the phone-lost procedure. The content key is *not* cleared
            // here: it is the phone's key, not a host's, and forgetting a host must not orphan
            // the encrypted messages it sent.
            passkeyStore.clear()
            // The per-host sweep above drops each proxy credential through removeHost; this
            // catches anything orphaned by an earlier build.
            proxyCredentials.clear()
            onDone()
        }
    }

    /** Forget which session to reopen per harness; the app lands on the newest one next time. */
    fun clearLastSessions(onDone: () -> Unit = {}) {
        viewModelScope.launch {
            hostsStore.clearLastSessions()
            onDone()
        }
    }

    private companion object {
        const val LOOPBACK = "127.0.0.1"
        const val DEFAULT_PORT = 3080
    }
}
