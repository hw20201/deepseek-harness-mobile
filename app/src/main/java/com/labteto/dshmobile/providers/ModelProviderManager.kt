package com.labteto.dshmobile.providers

import com.labteto.dshmobile.core.wire.DshApiClient
import com.labteto.dshmobile.core.wire.RpcResult
import com.labteto.dshmobile.core.wire.dto.CredentialInfo
import com.labteto.dshmobile.core.wire.dto.LlmConfigurableProvider
import com.labteto.dshmobile.core.wire.dto.LlmDiscoveredModel
import com.labteto.dshmobile.core.wire.dto.LlmModelDiscoveryRequest
import com.labteto.dshmobile.core.wire.dto.LlmProviderInfo
import com.labteto.dshmobile.core.wire.dto.SettingsDescribeValue
import com.labteto.dshmobile.core.wire.dto.SettingsNamespaceView
import com.labteto.dshmobile.core.wire.dto.SettingsPathOpView
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import javax.inject.Inject
import javax.inject.Singleton

/**
 * The wire calls the provider settings need, behind one seam so tests can fake them.
 * Every method is one [DshApiClient] call; nothing here knows about screens.
 */
interface ProviderWire {
    suspend fun listProviders(): RpcResult<List<LlmProviderInfo>>
    suspend fun listConfigurableProviders(): RpcResult<List<LlmConfigurableProvider>>
    suspend fun describeSettings(): RpcResult<SettingsDescribeValue>
    suspend fun describeCredentials(refs: List<String>): RpcResult<Map<String, CredentialInfo>>
    suspend fun discoverModels(
        settingsNs: String,
        request: LlmModelDiscoveryRequest,
    ): RpcResult<List<LlmDiscoveredModel>>

    suspend fun mutateSettings(
        ns: String,
        ops: List<SettingsPathOpView>,
        expectedRevision: Int?,
    ): RpcResult<SettingsNamespaceView>

    suspend fun setCredential(ref: String, value: String): RpcResult<JsonElement>
    suspend fun unsetCredential(ref: String): RpcResult<JsonElement>
}

/** [ProviderWire] over the live client. */
class DshApiProviderWire(private val api: DshApiClient) : ProviderWire {
    override suspend fun listProviders(): RpcResult<List<LlmProviderInfo>> =
        api.llmListProviders()

    override suspend fun listConfigurableProviders(): RpcResult<List<LlmConfigurableProvider>> =
        api.llmListConfigurableProviders()

    override suspend fun describeSettings(): RpcResult<SettingsDescribeValue> =
        api.settingsDescribe()

    override suspend fun describeCredentials(
        refs: List<String>,
    ): RpcResult<Map<String, CredentialInfo>> = api.credentialsDescribe(refs)

    override suspend fun discoverModels(
        settingsNs: String,
        request: LlmModelDiscoveryRequest,
    ): RpcResult<List<LlmDiscoveredModel>> = api.llmDiscoverModels(settingsNs, request)

    override suspend fun mutateSettings(
        ns: String,
        ops: List<SettingsPathOpView>,
        expectedRevision: Int?,
    ): RpcResult<SettingsNamespaceView> = api.settingsMutate(ns, ops, expectedRevision)

    override suspend fun setCredential(ref: String, value: String): RpcResult<JsonElement> =
        api.credentialsSet(ref, value)

    override suspend fun unsetCredential(ref: String): RpcResult<JsonElement> =
        api.credentialsUnset(ref)
}

/** Builds a [ProviderWire] for the live client; the manager resolves the client per call. */
fun interface ProviderWireFactory {
    fun create(api: DshApiClient): ProviderWire
}

/** What the Models card shows. */
data class ProvidersUiState(
    /** False while no harness is connected; the card then has nothing to read. */
    val connected: Boolean = false,
    val loading: Boolean = false,
    /** Configured providers (active or live), in the order the server lists them. */
    val rows: List<ProviderRow> = emptyList(),
    /** Unconfigured pi-ai routes the Add sheet can claim. */
    val claimable: List<ProviderRow> = emptyList(),
    /** The last error the card should show, if any. */
    val error: String? = null,
)

/** The outcome of one provider write, in the shape the Settings card toasts. */
sealed interface ProviderOutcome {
    data object Ok : ProviderOutcome

    /** No harness connected, so there is nothing to write to. */
    data object Offline : ProviderOutcome

    /** The server refused the write; the message is the server's own. */
    data class Failed(val message: String) : ProviderOutcome

    /** The settings revision moved under the writer (someone else saved first). */
    data object Conflict : ProviderOutcome
}

/** The outcome of asking an endpoint for its model list. */
sealed interface DiscoverOutcome {
    data class Found(val models: List<LlmDiscoveredModel>) : DiscoverOutcome
    data object Offline : DiscoverOutcome
    data class Failed(val message: String) : DiscoverOutcome
}

/**
 * Model providers: the Settings card's read and write side for third-party models.
 *
 * The flow follows the DSH web UI's Models settings page, the only other client that
 * writes these settings:
 * - read: `llm/listProviders` + `llm/listConfigurableProviders` + `settings/describe`
 *   (+ `credentials/describe` for the key state), joined into [ProviderRow]s;
 * - claim a built-in route: minimal path ops at the row's own `settingsPath`, so only
 *   the fields the card manages are named;
 * - declare a custom route: one `settings/mutate` set op with the whole profile at
 *   `providers.<route>` in `llm-pi-ai`;
 * - the key always travels separately through `credentials/set`, under the reference
 *   the profile records — it is never written into the settings document, never logged,
 *   and never stored on this phone;
 * - a write carries the namespace revision it was read at; a conflict re-reads the
 *   revision once and retries, then surfaces as [ProviderOutcome.Conflict].
 *
 * The model picker needs no change: it reads `session/modelCatalog`, and the Settings
 * screen re-reads the catalog after a successful save, so a new provider's models
 * appear there without a reconnect.
 *
 * The wire comes from a provider lambda (bound in `AppModule` to the live client), so
 * tests can hand the manager a fake wire without a connection.
 */
@Singleton
class ModelProviderManager @Inject constructor(
    private val wireProvider: () -> ProviderWire?,
) {
    private val _state = MutableStateFlow(ProvidersUiState())
    val state: StateFlow<ProvidersUiState> = _state.asStateFlow()

    /** Namespace revisions, for the CAS on the next write. */
    private var revisions: Map<String, Long> = emptyMap()

    /** The stored user-section profiles, the base the claim diff starts from. */
    private var userProfiles: Map<String, JsonObject> = emptyMap()

    private fun wire(): ProviderWire? = wireProvider()

    private fun revisionFor(ns: String): Int? =
        revisions[ns]?.let { if (it in Int.MIN_VALUE..Int.MAX_VALUE) it.toInt() else null }

    private fun failed(message: String): ProviderOutcome {
        _state.update { it.copy(loading = false, error = message) }
        return ProviderOutcome.Failed(message)
    }

    /** Re-reads the providers and the key state. The card calls this when it appears. */
    suspend fun refresh(): ProviderOutcome {
        val wire = wire() ?: run {
            _state.value = ProvidersUiState(connected = false)
            return ProviderOutcome.Offline
        }
        _state.update { it.copy(loading = true, error = null) }
        val live = when (val r = wire.listProviders()) {
            is RpcResult.Ok -> r.value
            is RpcResult.Err -> return failed(r.error.message)
        }
        val configurable = when (val r = wire.listConfigurableProviders()) {
            is RpcResult.Ok -> r.value
            is RpcResult.Err -> return failed(r.error.message)
        }
        val describe = when (val r = wire.describeSettings()) {
            is RpcResult.Ok -> r.value
            is RpcResult.Err -> return failed(r.error.message)
        }
        revisions = describe.namespaces.associate { it.ns to it.revision }
        val piAi = describe.namespaces.firstOrNull { it.ns == PROVIDER_SETTINGS_NS }
        val profiles = profilesOf(piAi?.value)
        userProfiles = profilesOf(piAi?.user)
        // The credential refs the configured rows resolve keys through. Key state is
        // advisory — a failed describe leaves it unknown rather than emptying the list.
        val refs = configurable.mapNotNull { row ->
            profiles[row.provider]?.stringField("apiKeyEnv")
                ?: if (row.active) deriveKeyRef(row.provider) else null
        }.distinct()
        val keyStates = if (refs.isEmpty()) {
            emptyMap()
        } else {
            when (val r = wire.describeCredentials(refs)) {
                is RpcResult.Ok -> r.value.mapValues { it.value.configured }
                is RpcResult.Err -> emptyMap()
            }
        }
        val joined = joinProviderRows(configurable, live, profiles, keyStates)
        _state.value = ProvidersUiState(
            connected = true,
            loading = false,
            rows = joined.filter { it.configured },
            claimable = joined.filter { !it.configured && it.editable },
            error = null,
        )
        return ProviderOutcome.Ok
    }

    /**
     * Asks an endpoint for its model list. The key, when given, is for this
     * interrogation alone — the harness never stores it.
     */
    suspend fun discover(
        settingsNs: String,
        provider: String?,
        baseUrl: String?,
        api: String?,
        apiKey: String?,
    ): DiscoverOutcome {
        val wire = wire() ?: return DiscoverOutcome.Offline
        val request = LlmModelDiscoveryRequest(
            provider = provider,
            baseURL = baseUrl?.takeIf { it.isNotBlank() },
            api = api,
            apiKey = apiKey?.takeIf { it.isNotBlank() },
        )
        return when (val r = wire.discoverModels(settingsNs, request)) {
            is RpcResult.Ok -> DiscoverOutcome.Found(r.value)
            is RpcResult.Err -> DiscoverOutcome.Failed(r.error.message)
        }
    }

    /**
     * Claims a built-in route: writes the fields the user changed at the row's own
     * settings path, then stores the key under the reference the profile names (its
     * own `apiKeyEnv`, or the derived reference when it names none). A null field
     * means "leave as stored"; a blank base URL clears the endpoint override. The
     * protocol is the one the claim sheet is using (the route's own, or the stored
     * profile's), and it is only used to check the endpoint for a doubled path.
     */
    suspend fun saveClaim(
        row: ProviderRow,
        api: String,
        baseUrl: String?,
        key: String?,
        models: List<ProviderModelDraft>?,
    ): ProviderOutcome {
        val wire = wire() ?: return ProviderOutcome.Offline
        val normalizedBase = baseUrl?.let(::normalizeBaseUrl)
        if (normalizedBase != null && normalizedBase.isNotBlank()) {
            validateBaseUrl(api, normalizedBase)?.let { problem ->
                return ProviderOutcome.Failed(baseUrlProblemMessage(api, problem))
            }
        }
        val keyValue = key?.trim().orEmpty()
        val keyRef = if (keyValue.isNotEmpty()) row.apiKeyEnv ?: deriveKeyRef(row.provider) else null
        val before: Map<String, JsonElement> = userProfiles[row.provider] ?: emptyMap()
        val after = before.toMutableMap()
        if (keyRef != null) after["apiKeyEnv"] = JsonPrimitive(keyRef)
        if (normalizedBase != null) {
            if (normalizedBase.isBlank()) after.remove("baseURL") else after["baseURL"] =
                JsonPrimitive(normalizedBase)
        }
        if (models != null) {
            after["models"] = JsonArray(models.map { it.toJson() })
        }
        val ops = buildClaimOps(row.settingsPath, before, after)
        if (ops.isNotEmpty()) {
            when (val r = mutateWithRetry(wire, row.settingsNs, ops, revisionFor(row.settingsNs))) {
                is RpcResult.Ok -> Unit
                is RpcResult.Err -> return writeFailed(r)
            }
        }
        if (keyRef != null) {
            when (val r = wire.setCredential(keyRef, keyValue)) {
                is RpcResult.Ok -> Unit
                is RpcResult.Err -> {
                    refresh()
                    return ProviderOutcome.Failed(r.error.message)
                }
            }
        }
        refresh()
        return ProviderOutcome.Ok
    }

    /**
     * Declares a custom route: one set op with the whole profile at
     * `providers.<route>`, then the key under the derived reference. The route id,
     * endpoint and at least one model are required — the same three fields the web
     * UI requires before it lets the create through.
     */
    suspend fun saveCustom(
        route: String,
        displayName: String?,
        baseUrl: String,
        api: String,
        models: List<ProviderModelDraft>,
        key: String?,
    ): ProviderOutcome {
        val wire = wire() ?: return ProviderOutcome.Offline
        val trimmedRoute = route.trim()
        if (!isValidRouteId(trimmedRoute)) {
            return ProviderOutcome.Failed("Route id must start with a letter, using only lowercase letters, digits and hyphens.")
        }
        if (_state.value.rows.any { it.provider == trimmedRoute } ||
            _state.value.claimable.any { it.provider == trimmedRoute }
        ) {
            return ProviderOutcome.Failed("A provider with this route id already exists.")
        }
        val normalizedBase = normalizeBaseUrl(baseUrl)
        validateBaseUrl(api, normalizedBase)?.let { problem ->
            return ProviderOutcome.Failed(baseUrlProblemMessage(api, problem))
        }
        if (models.isEmpty()) {
            return ProviderOutcome.Failed("A custom provider needs at least one model.")
        }
        val keyValue = key?.trim().orEmpty()
        val keyRef = if (keyValue.isNotEmpty()) deriveKeyRef(trimmedRoute) else null
        val profile = buildCustomProfile(
            displayName = displayName?.trim(),
            keyRef = keyRef,
            api = api,
            baseUrl = normalizedBase,
            models = models,
        )
        val op = SettingsPathOpView.Set(
            path = listOf("providers", trimmedRoute),
            value = profile,
        )
        when (val r = mutateWithRetry(wire, PROVIDER_SETTINGS_NS, listOf(op), revisionFor(PROVIDER_SETTINGS_NS))) {
            is RpcResult.Ok -> Unit
            is RpcResult.Err -> return writeFailed(r)
        }
        if (keyRef != null) {
            when (val r = wire.setCredential(keyRef, keyValue)) {
                is RpcResult.Ok -> Unit
                is RpcResult.Err -> {
                    refresh()
                    return ProviderOutcome.Failed(r.error.message)
                }
            }
        }
        refresh()
        return ProviderOutcome.Ok
    }

    /**
     * Removes a provider: unsets its profile, then clears the key slot best-effort.
     * The profile is gone either way, and a leftover credential nothing references
     * is inert — which is why the key step never fails the removal.
     */
    suspend fun remove(row: ProviderRow): ProviderOutcome {
        val wire = wire() ?: return ProviderOutcome.Offline
        val ops = listOf<SettingsPathOpView>(SettingsPathOpView.Unset(row.settingsPath))
        when (val r = mutateWithRetry(wire, row.settingsNs, ops, revisionFor(row.settingsNs))) {
            is RpcResult.Ok -> Unit
            is RpcResult.Err -> return writeFailed(r)
        }
        (row.apiKeyEnv ?: deriveKeyRef(row.provider)).let { ref ->
            runCatching { wire.unsetCredential(ref) }
        }
        refresh()
        return ProviderOutcome.Ok
    }

    private fun writeFailed(r: RpcResult.Err): ProviderOutcome =
        if (r.error.code == SETTINGS_CONFLICT_CODE) ProviderOutcome.Conflict
        else ProviderOutcome.Failed(r.error.message)

    /**
     * One mutate, retried once on a revision conflict after re-reading the revision.
     * A second conflict surfaces as the error, so the caller can say "someone else
     * saved first" instead of silently overwriting.
     */
    private suspend fun mutateWithRetry(
        wire: ProviderWire,
        ns: String,
        ops: List<SettingsPathOpView>,
        revision: Int?,
    ): RpcResult<SettingsNamespaceView> {
        var current = revision
        repeat(2) { attempt ->
            when (val r = wire.mutateSettings(ns, ops, current)) {
                is RpcResult.Ok -> return r
                is RpcResult.Err -> {
                    if (r.error.code != SETTINGS_CONFLICT_CODE || attempt == 1) return r
                    val fresh = wire.describeSettings()
                    val freshRevision = (fresh as? RpcResult.Ok)?.value?.namespaces
                        ?.firstOrNull { it.ns == ns }?.revision
                        ?.let { if (it in Int.MIN_VALUE..Int.MAX_VALUE) it.toInt() else null }
                        ?: return r
                    current = freshRevision
                }
            }
        }
        error("mutateWithRetry fell through")
    }

    private fun baseUrlProblemMessage(api: String, problem: BaseUrlProblem): String = when (problem) {
        BaseUrlProblem.NOT_HTTP_URL -> "The endpoint must be an http(s) URL."
        BaseUrlProblem.REDUNDANT_PATH_SUFFIX ->
            "Drop the trailing ${redundantSuffixHint(api) ?: "path"} — the SDK appends it itself."
    }
}
