package com.labteto.dshmobile.providers

import com.labteto.dshmobile.core.wire.dto.LlmConfigurableProvider
import com.labteto.dshmobile.core.wire.dto.LlmProviderInfo
import com.labteto.dshmobile.core.wire.dto.SettingsPathOpView
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The provider draft rules: the credential reference, the route id, the endpoint
 * check, the profile payload and the minimal claim ops. All ported from the DSH web
 * UI's Models settings page, so a drift here is a drift from the only other client
 * that writes these settings.
 */
class ProviderDraftsTest {

    @Test
    fun `deriveKeyRef uppercases and collapses separators`() {
        assertEquals("ANTHROPIC_API_KEY", deriveKeyRef("anthropic"))
        assertEquals("OPENAI_API_KEY", deriveKeyRef("openai"))
        assertEquals("MINIMAX_CN_API_KEY", deriveKeyRef("minimax-cn"))
        assertEquals("MY_GATEWAY_API_KEY", deriveKeyRef("my-gateway"))
    }

    @Test
    fun `route ids start with a letter and use lowercase hyphens`() {
        assertTrue(isValidRouteId("openai"))
        assertTrue(isValidRouteId("acme-gateway"))
        assertTrue(isValidRouteId("acme2"))
        assertFalse(isValidRouteId("OpenAI"))
        assertFalse(isValidRouteId("1abc"))
        assertFalse(isValidRouteId("a_b"))
        assertFalse(isValidRouteId(""))
        assertFalse(isValidRouteId("a--b"))
        assertFalse(isValidRouteId("a-"))
        assertFalse(isValidRouteId("-a"))
    }

    @Test
    fun `normalizeBaseUrl trims whitespace and trailing slashes`() {
        assertEquals("https://api.openai.com/v1", normalizeBaseUrl("  https://api.openai.com/v1/  "))
        assertEquals("https://example.com", normalizeBaseUrl("https://example.com///"))
    }

    @Test
    fun `anthropic endpoints must not carry the path the SDK appends`() {
        assertNull(validateBaseUrl(ProviderProtocols.ANTHROPIC_MESSAGES, "https://api.anthropic.com"))
        assertNull(validateBaseUrl(ProviderProtocols.ANTHROPIC_MESSAGES, "https://api.minimax.io/anthropic"))
        assertEquals(
            BaseUrlProblem.REDUNDANT_PATH_SUFFIX,
            validateBaseUrl(ProviderProtocols.ANTHROPIC_MESSAGES, "https://relay.example.com/v1/messages"),
        )
        assertEquals(
            BaseUrlProblem.REDUNDANT_PATH_SUFFIX,
            validateBaseUrl(ProviderProtocols.ANTHROPIC_MESSAGES, "https://relay.example.com/v1"),
        )
    }

    @Test
    fun `openai endpoints must not carry the path the SDK appends`() {
        assertNull(validateBaseUrl(ProviderProtocols.OPENAI_COMPLETIONS, "https://api.openai.com/v1"))
        assertEquals(
            BaseUrlProblem.REDUNDANT_PATH_SUFFIX,
            validateBaseUrl(ProviderProtocols.OPENAI_COMPLETIONS, "https://relay.example.com/v1/chat/completions"),
        )
        assertEquals(
            BaseUrlProblem.REDUNDANT_PATH_SUFFIX,
            validateBaseUrl(ProviderProtocols.OPENAI_RESPONSES, "https://relay.example.com/responses"),
        )
    }

    @Test
    fun `non http endpoints are rejected`() {
        assertEquals(BaseUrlProblem.NOT_HTTP_URL, validateBaseUrl(ProviderProtocols.OPENAI_COMPLETIONS, "not a url"))
        assertEquals(BaseUrlProblem.NOT_HTTP_URL, validateBaseUrl(ProviderProtocols.OPENAI_COMPLETIONS, "ftp://example.com/v1"))
        assertEquals(BaseUrlProblem.NOT_HTTP_URL, validateBaseUrl(ProviderProtocols.OPENAI_COMPLETIONS, ""))
        assertEquals(BaseUrlProblem.NOT_HTTP_URL, validateBaseUrl(ProviderProtocols.OPENAI_COMPLETIONS, "https://"))
    }

    @Test
    fun `custom profile carries only the fields the user gave`() {
        val profile = buildCustomProfile(
            displayName = null,
            keyRef = "ACME_API_KEY",
            api = ProviderProtocols.ANTHROPIC_MESSAGES,
            baseUrl = "https://relay.example.com",
            models = listOf(
                ProviderModelDraft(id = "claude-sonnet-4-5", name = "Sonnet", contextWindow = 200000),
                ProviderModelDraft(id = "claude-haiku-4-5"),
            ),
        )
        assertFalse("displayName" in profile)
        assertEquals("ACME_API_KEY", profile.stringField("apiKeyEnv"))
        assertEquals(ProviderProtocols.ANTHROPIC_MESSAGES, profile.stringField("api"))
        assertEquals("https://relay.example.com", profile.stringField("baseURL"))
        assertEquals(listOf("claude-sonnet-4-5", "claude-haiku-4-5"), profile.modelIds())
        val first = (profile["models"] as kotlinx.serialization.json.JsonArray)[0] as JsonObject
        assertEquals("Sonnet", first.stringField("name"))
        assertEquals("200000", first["contextWindow"].toString())
        assertFalse("maxTokens" in first)
    }

    @Test
    fun `custom profile without a key omits apiKeyEnv`() {
        val profile = buildCustomProfile(
            displayName = "Acme",
            keyRef = null,
            api = ProviderProtocols.OPENAI_COMPLETIONS,
            baseUrl = "https://relay.example.com/v1",
            models = listOf(ProviderModelDraft(id = "gpt-5")),
        )
        assertEquals("Acme", profile.stringField("displayName"))
        assertFalse("apiKeyEnv" in profile)
    }

    @Test
    fun `claim ops name only the fields that changed`() {
        val path = listOf("providers", "openai")
        val before = mapOf(
            "apiKeyEnv" to JsonPrimitive("OPENAI_API_KEY"),
            "baseURL" to JsonPrimitive("https://api.openai.com/v1"),
        )
        val after = mapOf(
            "apiKeyEnv" to JsonPrimitive("OPENAI_API_KEY"),
            "baseURL" to JsonPrimitive("https://relay.example.com/v1"),
            "models" to buildJsonObject { put("x", JsonPrimitive(1)) },
        )
        val ops = buildClaimOps(path, before, after)
        // apiKeyEnv unchanged -> no op; baseURL changed -> set; models new -> set.
        assertEquals(2, ops.size)
        assertTrue(ops[0] is SettingsPathOpView.Set)
        assertEquals(listOf("providers", "openai", "baseURL"), (ops[0] as SettingsPathOpView.Set).path)
        assertEquals(listOf("providers", "openai", "models"), (ops[1] as SettingsPathOpView.Set).path)
    }

    @Test
    fun `claim ops unset a field the user cleared and stay empty when nothing changed`() {
        val path = listOf("providers", "openai")
        val before = mapOf(
            "baseURL" to JsonPrimitive("https://relay.example.com/v1"),
            "apiKeyEnv" to JsonPrimitive("OPENAI_API_KEY"),
        )
        val cleared = mapOf("apiKeyEnv" to JsonPrimitive("OPENAI_API_KEY"))
        val ops = buildClaimOps(path, before, cleared)
        assertEquals(1, ops.size)
        assertTrue(ops[0] is SettingsPathOpView.Unset)
        assertEquals(listOf("providers", "openai", "baseURL"), (ops[0] as SettingsPathOpView.Unset).path)

        assertTrue(buildClaimOps(path, before, before).isEmpty())
    }

    @Test
    fun `implied protocol prefers the stored api then the route family`() {
        assertEquals(
            ProviderProtocols.ANTHROPIC_MESSAGES,
            impliedProtocol("openai", ProviderProtocols.ANTHROPIC_MESSAGES),
        )
        assertEquals(ProviderProtocols.ANTHROPIC_MESSAGES, impliedProtocol("anthropic", null))
        assertEquals(ProviderProtocols.ANTHROPIC_MESSAGES, impliedProtocol("minimax-cn", null))
        assertEquals(ProviderProtocols.OPENAI_COMPLETIONS, impliedProtocol("openai", null))
        assertEquals(ProviderProtocols.OPENAI_COMPLETIONS, impliedProtocol("acme-gateway", null))
    }

    @Test
    fun `join marks configured from active or live and reads the stored profile`() {
        val configurable = listOf(
            LlmConfigurableProvider(
                provider = "openai",
                displayName = "OpenAI",
                settingsNs = PROVIDER_SETTINGS_NS,
                settingsPath = listOf("providers", "openai"),
                active = false,
                declared = false,
            ),
            LlmConfigurableProvider(
                provider = "deepseek-official",
                displayName = "DeepSeek",
                settingsNs = "llm-deepseek",
                settingsPath = listOf("deepseek"),
                active = true,
                declared = true,
            ),
            LlmConfigurableProvider(
                provider = "anthropic",
                displayName = "Anthropic",
                settingsNs = PROVIDER_SETTINGS_NS,
                settingsPath = listOf("providers", "anthropic"),
                active = false,
                declared = false,
            ),
        )
        val live = listOf(LlmProviderInfo(id = "deepseek-official", name = "DeepSeek"))
        val profiles = mapOf(
            "openai" to buildJsonObject {
                put("apiKeyEnv", JsonPrimitive("OPENAI_API_KEY"))
                put("baseURL", JsonPrimitive("https://relay.example.com/v1"))
                put("api", JsonPrimitive(ProviderProtocols.OPENAI_COMPLETIONS))
            },
        )
        val rows = joinProviderRows(
            configurable = configurable,
            live = live,
            profiles = profiles,
            keyStates = mapOf("OPENAI_API_KEY" to true),
        )
        val openai = rows.first { it.provider == "openai" }
        assertFalse(openai.configured)
        assertTrue(openai.editable)
        assertEquals("OPENAI_API_KEY", openai.apiKeyEnv)
        assertEquals("https://relay.example.com/v1", openai.baseUrl)
        assertEquals(ProviderProtocols.OPENAI_COMPLETIONS, openai.api)
        assertEquals(true, openai.keySet)

        val deepseek = rows.first { it.provider == "deepseek-official" }
        assertTrue(deepseek.configured)
        assertTrue(deepseek.live)
        assertFalse(deepseek.editable)
        assertNull(deepseek.apiKeyEnv)
        assertNull(deepseek.keySet)

        val anthropic = rows.first { it.provider == "anthropic" }
        assertFalse(anthropic.configured)
        assertNull(anthropic.keySet)
    }
}
