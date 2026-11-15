package com.labteto.dshmobile.providers

import com.labteto.dshmobile.core.wire.dto.LlmConfigurableProvider
import com.labteto.dshmobile.core.wire.dto.LlmProviderInfo
import com.labteto.dshmobile.core.wire.dto.SettingsPathOpView
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import java.net.URL

/**
 * Provider drafts: the pure rules for adding a third-party model provider, ported from the
 * DSH web UI's Models settings page (`dsh-client-ui-settings-models`, DSH 0.2.1-rc.2).
 *
 * The web page is the reference implementation — it is the only other client that writes
 * these settings, and the shapes below are its shapes:
 * - a hand-declared route lives at `providers.<route>` in the `llm-pi-ai` namespace,
 *   written by one `settings/mutate` set op; its key travels separately through
 *   `credentials/set` under the reference the profile records as `apiKeyEnv`;
 * - the reference is derived from the route id (`deriveKeyRef`);
 * - a route id is lowercase alphanumerics and hyphens, starting with a letter;
 * - a hand-declared route needs an endpoint, a protocol, and at least one model;
 * - the endpoint must not carry the path the SDK appends itself (`/v1/messages` for
 *   Anthropic, `/chat/completions` and `/responses` for OpenAI).
 *
 * Nothing here touches the wire: these are the payloads and the validation, so they can
 * be tested without a harness.
 */

/** The settings namespace a hand-declared provider is written into (the web UI's NS). */
const val PROVIDER_SETTINGS_NS = "llm-pi-ai"

/** The error code a `settings/mutate` answers when the revision moved under the writer. */
const val SETTINGS_CONFLICT_CODE = "settings/conflict"

/** Wire protocols a hand-declared route may name. */
object ProviderProtocols {
    const val OPENAI_COMPLETIONS = "openai-completions"
    const val OPENAI_RESPONSES = "openai-responses"
    const val ANTHROPIC_MESSAGES = "anthropic-messages"

    /** All three, in the order the web UI's protocol picker offers them. */
    val ALL = listOf(OPENAI_COMPLETIONS, OPENAI_RESPONSES, ANTHROPIC_MESSAGES)

    fun isAnthropic(api: String): Boolean = api == ANTHROPIC_MESSAGES
}

/**
 * The credential reference a route id resolves keys through: the id uppercased, every
 * non-alphanumeric run collapsed to one `_`, plus `_API_KEY`. The web UI's `deriveKeyRef`;
 * `anthropic` -> `ANTHROPIC_API_KEY`, `minimax-cn` -> `MINIMAX_CN_API_KEY`.
 */
fun deriveKeyRef(provider: String): String =
    provider.uppercase().replace(Regex("[^A-Z0-9]+"), "_") + "_API_KEY"

/**
 * A route id usable as a settings key and as the stem of a credential name (the web UI's
 * ROUTE_PATTERN). The leading letter is the second half of that: a credential reference
 * is a POSIX shell identifier, which cannot start with a digit.
 */
private val ROUTE_PATTERN = Regex("^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")

fun isValidRouteId(route: String): Boolean = ROUTE_PATTERN.matches(route)

/** What is wrong with a base URL, if anything. */
enum class BaseUrlProblem {
    /** Not an http(s) URL, or no host in it. */
    NOT_HTTP_URL,

    /** Carries the path the SDK appends itself — the request would double it. */
    REDUNDANT_PATH_SUFFIX,
}

/** The path suffixes one protocol's SDK appends, for the hint that names them. */
fun redundantSuffixHint(api: String): String? = when (api) {
    ProviderProtocols.ANTHROPIC_MESSAGES -> "/v1/messages or /v1"
    ProviderProtocols.OPENAI_COMPLETIONS -> "/chat/completions"
    ProviderProtocols.OPENAI_RESPONSES -> "/responses"
    else -> null
}

/** A base URL with the whitespace and the trailing slashes taken off. */
fun normalizeBaseUrl(raw: String): String = raw.trim().trimEnd('/')

/**
 * Validates a base URL for one protocol. The SDK appends its own path (`/v1/messages`
 * for Anthropic, `/chat/completions` for OpenAI Chat Completions, `/responses` for
 * OpenAI Responses), so an endpoint that already ends in one of those would double it.
 * A relay that serves Anthropic under its own path (say `/anthropic`) is fine — the
 * check only rejects the suffixes the SDK itself adds.
 */
fun validateBaseUrl(api: String, raw: String): BaseUrlProblem? {
    val url = normalizeBaseUrl(raw)
    val parsed = runCatching { URL(url) }.getOrNull()
    if (parsed == null || (parsed.protocol != "http" && parsed.protocol != "https") ||
        parsed.host.isNullOrBlank()
    ) {
        return BaseUrlProblem.NOT_HTTP_URL
    }
    val suffixes = when (api) {
        ProviderProtocols.ANTHROPIC_MESSAGES -> listOf("/v1/messages", "/v1")
        ProviderProtocols.OPENAI_COMPLETIONS -> listOf("/chat/completions")
        ProviderProtocols.OPENAI_RESPONSES -> listOf("/responses")
        else -> emptyList()
    }
    if (suffixes.any { url.endsWith(it) }) return BaseUrlProblem.REDUNDANT_PATH_SUFFIX
    return null
}

/** One model row of a provider profile, as the user drafted it. */
data class ProviderModelDraft(
    val id: String,
    val name: String? = null,
    val contextWindow: Int? = null,
    val maxTokens: Int? = null,
)

fun ProviderModelDraft.toJson(): JsonObject = buildJsonObject {
    put("id", JsonPrimitive(id))
    name?.takeIf { it.isNotBlank() }?.let { put("name", JsonPrimitive(it)) }
    contextWindow?.let { put("contextWindow", JsonPrimitive(it)) }
    maxTokens?.let { put("maxTokens", JsonPrimitive(it)) }
}

/**
 * The whole profile of a hand-declared route, as one `settings/mutate` set op writes it
 * at `providers.<route>`. The display name and the key reference are present only when
 * the user gave them; a route with no key is written without `apiKeyEnv` and cannot serve
 * until a key is set.
 */
fun buildCustomProfile(
    displayName: String?,
    keyRef: String?,
    api: String,
    baseUrl: String,
    models: List<ProviderModelDraft>,
): JsonObject = buildJsonObject {
    displayName?.takeIf { it.isNotBlank() }?.let { put("displayName", JsonPrimitive(it)) }
    keyRef?.let { put("apiKeyEnv", JsonPrimitive(it)) }
    put("api", JsonPrimitive(api))
    put("baseURL", JsonPrimitive(baseUrl))
    put("models", JsonArray(models.map { it.toJson() }))
}

/**
 * The minimal path ops carrying `after` over `before`, both as the card sees them — the
 * web UI's `pathOps`. Only keys the card observed are named; fields absent from both
 * sides produce no op, which is why edits are path-addressed rather than a rebuilt
 * section. `before` is the stored user-section profile (absent -> empty); `after` is
 * that profile with the user's edits applied.
 */
fun buildClaimOps(
    settingsPath: List<String>,
    before: Map<String, JsonElement>,
    after: Map<String, JsonElement>,
): List<SettingsPathOpView> {
    val ops = mutableListOf<SettingsPathOpView>()
    for ((key, value) in after) {
        if (before[key] != value) {
            ops += SettingsPathOpView.Set(settingsPath + key, value)
        }
    }
    for (key in before.keys) {
        if (key !in after) {
            ops += SettingsPathOpView.Unset(settingsPath + key)
        }
    }
    return ops
}

/**
 * The protocol a built-in route speaks, for the endpoint check: the stored profile's
 * `api` when it names one, else the adapter's own default for the route. The common
 * claim targets are OpenAI-format (`openai`, …) and Anthropic-format (`anthropic`,
 * `minimax`, …); anything else takes the Chat Completions default, and the claim
 * sheet shows the protocol so the user can correct it.
 */
fun impliedProtocol(provider: String, storedApi: String?): String {
    if (!storedApi.isNullOrBlank()) return storedApi
    return if (provider.startsWith("anthropic") || provider.startsWith("minimax")) {
        ProviderProtocols.ANTHROPIC_MESSAGES
    } else {
        ProviderProtocols.OPENAI_COMPLETIONS
    }
}

/** The stored profile object for one provider inside a namespace value, if any. */
fun profileAt(namespaceValue: JsonElement?, provider: String): JsonObject? =
    (namespaceValue as? JsonObject)
        ?.get("providers")?.let { it as? JsonObject }
        ?.get(provider)?.let { it as? JsonObject }

/** The provider profiles inside one namespace value, keyed by route id. */
fun profilesOf(namespaceValue: JsonElement?): Map<String, JsonObject> {
    val providers = (namespaceValue as? JsonObject)?.get("providers") as? JsonObject
        ?: return emptyMap()
    return providers.entries.mapNotNull { (key, element) ->
        (element as? JsonObject)?.let { key to it }
    }.toMap()
}

/** A string field of a profile object, blank counting as absent. */
fun JsonObject.stringField(name: String): String? =
    (get(name) as? JsonPrimitive)?.contentOrNull?.takeIf { it.isNotBlank() }

/** The model ids a stored profile declares. */
fun JsonObject.modelIds(): List<String> =
    (get("models") as? JsonArray).orEmpty()
        .mapNotNull { (it as? JsonObject)?.stringField("id") }

/**
 * One provider row as the Settings card shows it.
 *
 * The row is a join of three facts: the configurable route the server lists, whether
 * it can serve a request right now, and the profile the user section stores for it.
 */
data class ProviderRow(
    val provider: String,
    val displayName: String,
    val settingsNs: String,
    val settingsPath: List<String>,
    /** The adapter's own active flag, or true when the route is live right now. */
    val configured: Boolean,
    /** Present when the adapter draws a shipped-vs-declared distinction. */
    val declared: Boolean?,
    /** Whether the route can serve a request right now. */
    val live: Boolean,
    /** The credential reference the stored profile names, if it names one. */
    val apiKeyEnv: String?,
    /** The wire protocol the stored profile names, if it names one. */
    val api: String?,
    /** The endpoint override the stored profile carries, if it carries one. */
    val baseUrl: String?,
    /** The model ids the stored profile declares, if it declares any. */
    val modelIds: List<String>,
    /** Whether a key is stored under the reference, when that was described. */
    val keySet: Boolean?,
) {
    /** Whether this row can be claimed or edited here: pi-ai routes only. */
    val editable: Boolean get() = settingsNs == PROVIDER_SETTINGS_NS
}

/**
 * Joins the configurable routes with the live routes and the stored profiles, into the
 * rows the card shows. The credential reference a row resolves keys through is the one
 * its stored profile names, or the derived reference when the profile names none.
 */
fun joinProviderRows(
    configurable: List<LlmConfigurableProvider>,
    live: List<LlmProviderInfo>,
    profiles: Map<String, JsonObject>,
    keyStates: Map<String, Boolean>,
): List<ProviderRow> {
    val liveIds = live.map { it.id }.toSet()
    return configurable.map { row ->
        val profile = profiles[row.provider]
        val apiKeyEnv = profile?.stringField("apiKeyEnv")
        val keyRef = apiKeyEnv ?: deriveKeyRef(row.provider)
        ProviderRow(
            provider = row.provider,
            displayName = row.displayName,
            settingsNs = row.settingsNs,
            settingsPath = row.settingsPath,
            configured = row.active || row.provider in liveIds,
            declared = row.declared,
            live = row.provider in liveIds,
            apiKeyEnv = apiKeyEnv,
            api = profile?.stringField("api"),
            baseUrl = profile?.stringField("baseURL"),
            modelIds = profile?.modelIds().orEmpty(),
            keySet = keyStates[keyRef],
        )
    }
}
