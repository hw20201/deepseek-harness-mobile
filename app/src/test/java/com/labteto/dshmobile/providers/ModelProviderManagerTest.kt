package com.labteto.dshmobile.providers

import com.labteto.dshmobile.core.wire.RpcResult
import com.labteto.dshmobile.core.wire.RpcError
import com.labteto.dshmobile.core.wire.dto.CredentialInfo
import com.labteto.dshmobile.core.wire.dto.LlmConfigurableProvider
import com.labteto.dshmobile.core.wire.dto.LlmDiscoveredModel
import com.labteto.dshmobile.core.wire.dto.LlmModelDiscoveryRequest
import com.labteto.dshmobile.core.wire.dto.LlmProviderInfo
import com.labteto.dshmobile.core.wire.dto.SettingsDescribeValue
import com.labteto.dshmobile.core.wire.dto.SettingsNamespaceView
import com.labteto.dshmobile.core.wire.dto.SettingsPathOpView
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The manager against a fake wire: the refresh join, the claim/custom save order
 * (settings first, key second), and the one conflict retry. The payloads themselves
 * are covered by [ProviderDraftsTest]; these tests cover the orchestration — that
 * the right calls happen, in the right order, and that a refusal surfaces instead
 * of being swallowed.
 */
class ModelProviderManagerTest {

    private class FakeWire : ProviderWire {
        var live: List<LlmProviderInfo> = emptyList()
        var configurable: List<LlmConfigurableProvider> = emptyList()
        var describeValue: SettingsDescribeValue = SettingsDescribeValue(
            writable = true,
            hasDocument = true,
            namespaces = emptyList(),
        )
        var keyStates: Map<String, CredentialInfo> = emptyMap()
        var discoverModels: List<LlmDiscoveredModel> = emptyList()
        var listProvidersError: RpcError? = null
        var discoverError: RpcError? = null

        /** Queued mutate answers, in order; empty means "written". */
        val mutateAnswers = ArrayDeque<RpcResult<SettingsNamespaceView>>()
        var setCredentialError: RpcError? = null

        val calls = mutableListOf<String>()
        var describeCalls = 0
        val mutateCalls = mutableListOf<Triple<String, List<SettingsPathOpView>, Int?>>()
        val setCredentials = mutableListOf<Pair<String, String>>()
        val unsetCredentials = mutableListOf<String>()
        var lastDiscover: Pair<String, LlmModelDiscoveryRequest>? = null

        private fun namespaceView(): SettingsNamespaceView = SettingsNamespaceView(
            ns = PROVIDER_SETTINGS_NS,
            schema = buildJsonObject {},
            value = buildJsonObject {},
            applies = "live",
            revision = 7L,
        )

        override suspend fun listProviders(): RpcResult<List<LlmProviderInfo>> {
            calls += "listProviders"
            return listProvidersError?.let { RpcResult.Err(it) } ?: RpcResult.Ok(live)
        }

        override suspend fun listConfigurableProviders(): RpcResult<List<LlmConfigurableProvider>> {
            calls += "listConfigurableProviders"
            return RpcResult.Ok(configurable)
        }

        override suspend fun describeSettings(): RpcResult<SettingsDescribeValue> {
            calls += "describeSettings"
            describeCalls++
            return RpcResult.Ok(describeValue)
        }

        override suspend fun describeCredentials(
            refs: List<String>,
        ): RpcResult<Map<String, CredentialInfo>> {
            calls += "describeCredentials"
            return RpcResult.Ok(keyStates)
        }

        override suspend fun discoverModels(
            settingsNs: String,
            request: LlmModelDiscoveryRequest,
        ): RpcResult<List<LlmDiscoveredModel>> {
            calls += "discoverModels"
            lastDiscover = settingsNs to request
            return discoverError?.let { RpcResult.Err(it) } ?: RpcResult.Ok(discoverModels)
        }

        override suspend fun mutateSettings(
            ns: String,
            ops: List<SettingsPathOpView>,
            expectedRevision: Int?,
        ): RpcResult<SettingsNamespaceView> {
            calls += "mutateSettings"
            mutateCalls += Triple(ns, ops, expectedRevision)
            return mutateAnswers.removeFirstOrNull() ?: RpcResult.Ok(namespaceView())
        }

        override suspend fun setCredential(ref: String, value: String): RpcResult<JsonElement> {
            calls += "setCredential"
            setCredentials += ref to value
            return setCredentialError?.let { RpcResult.Err(it) } ?: RpcResult.Ok(buildJsonObject {})
        }

        override suspend fun unsetCredential(ref: String): RpcResult<JsonElement> {
            calls += "unsetCredential"
            unsetCredentials += ref
            return RpcResult.Ok(buildJsonObject {})
        }
    }

    private fun configurable(
        provider: String,
        displayName: String = provider,
        ns: String = PROVIDER_SETTINGS_NS,
        active: Boolean = false,
    ) = LlmConfigurableProvider(
        provider = provider,
        displayName = displayName,
        settingsNs = ns,
        settingsPath = listOf("providers", provider),
        active = active,
        declared = false,
    )

    private fun piAiNamespace(
        value: JsonObject = buildJsonObject {},
        user: JsonObject = buildJsonObject {},
        revision: Long = 7L,
    ) = SettingsNamespaceView(
        ns = PROVIDER_SETTINGS_NS,
        schema = buildJsonObject {},
        value = value,
        user = user,
        applies = "live",
        revision = revision,
    )

    private fun describe(vararg namespaces: SettingsNamespaceView) =
        SettingsDescribeValue(writable = true, hasDocument = true, namespaces = namespaces.toList())

    private fun manager(wire: ProviderWire?) = ModelProviderManager(wireProvider = { wire })

    @Test
    fun `refresh joins live, configurable, profiles and key state`() = runTest {
        val wire = FakeWire().apply {
            live = listOf(LlmProviderInfo(id = "deepseek-official", name = "DeepSeek"))
            configurable = listOf(
                configurable("openai", active = true),
                configurable("deepseek-official", ns = "llm-deepseek", active = true),
                configurable("anthropic"),
            )
            describeValue = describe(
                piAiNamespace(
                    value = buildJsonObject {
                        put("providers", buildJsonObject {
                            put("openai", buildJsonObject {
                                put("apiKeyEnv", JsonPrimitive("OPENAI_API_KEY"))
                                put("baseURL", JsonPrimitive("https://relay.example.com/v1"))
                                put("api", JsonPrimitive(ProviderProtocols.OPENAI_COMPLETIONS))
                            })
                        })
                    },
                    user = buildJsonObject {
                        put("providers", buildJsonObject {
                            put("openai", buildJsonObject {
                                put("apiKeyEnv", JsonPrimitive("OPENAI_API_KEY"))
                            })
                        })
                    },
                ),
            )
            keyStates = mapOf("OPENAI_API_KEY" to CredentialInfo(configured = true))
        }
        val m = manager(wire)
        assertEquals(ProviderOutcome.Ok, m.refresh())

        val state = m.state.value
        assertTrue(state.connected)
        assertEquals(listOf("openai", "deepseek-official"), state.rows.map { it.provider })
        val openai = state.rows.first { it.provider == "openai" }
        assertEquals("OPENAI_API_KEY", openai.apiKeyEnv)
        assertEquals("https://relay.example.com/v1", openai.baseUrl)
        assertEquals(true, openai.keySet)
        assertTrue(state.rows.first { it.provider == "deepseek-official" }.live)
        assertFalse(state.rows.first { it.provider == "deepseek-official" }.editable)
        assertEquals(listOf("anthropic"), state.claimable.map { it.provider })
    }

    @Test
    fun `refresh reports offline without a wire`() = runTest {
        val m = manager(null)
        assertEquals(ProviderOutcome.Offline, m.refresh())
        assertFalse(m.state.value.connected)
    }

    @Test
    fun `refresh surfaces a server refusal`() = runTest {
        val wire = FakeWire().apply {
            listProvidersError = RpcError(code = "boom", message = "nope")
        }
        val m = manager(wire)
        val outcome = m.refresh()
        assertTrue(outcome is ProviderOutcome.Failed)
        assertEquals("nope", (outcome as ProviderOutcome.Failed).message)
        assertEquals("nope", m.state.value.error)
    }

    @Test
    fun `discover passes the draft through and maps the answer`() = runTest {
        val wire = FakeWire().apply {
            discoverModels = listOf(
                LlmDiscoveredModel(id = "gpt-5", name = "GPT-5", contextWindow = 400000),
            )
        }
        val m = manager(wire)
        val found = m.discover(
            settingsNs = PROVIDER_SETTINGS_NS,
            provider = "openai",
            baseUrl = "https://relay.example.com/v1",
            api = ProviderProtocols.OPENAI_COMPLETIONS,
            apiKey = "secret",
        )
        assertTrue(found is DiscoverOutcome.Found)
        assertEquals(listOf("gpt-5"), (found as DiscoverOutcome.Found).models.map { it.id })
        val (ns, request) = wire.lastDiscover!!
        assertEquals(PROVIDER_SETTINGS_NS, ns)
        assertEquals("openai", request.provider)
        assertEquals("https://relay.example.com/v1", request.baseURL)
        assertEquals("secret", request.apiKey)

        assertEquals(DiscoverOutcome.Offline, manager(null).discover(PROVIDER_SETTINGS_NS, null, null, null, null))
    }

    @Test
    fun `saveCustom writes the profile then the key, in that order`() = runTest {
        val wire = FakeWire().apply {
            configurable = listOf(configurable("openai"))
            describeValue = describe(piAiNamespace())
        }
        val m = manager(wire)
        assertEquals(ProviderOutcome.Ok, m.refresh())
        val outcome = m.saveCustom(
            route = "acme",
            displayName = "Acme",
            baseUrl = "https://relay.example.com",
            api = ProviderProtocols.ANTHROPIC_MESSAGES,
            models = listOf(ProviderModelDraft(id = "claude-sonnet-4-5")),
            key = "secret-key",
        )
        assertEquals(ProviderOutcome.Ok, outcome)
        assertTrue(wire.calls.indexOf("mutateSettings") < wire.calls.indexOf("setCredential"))
        val (ns, ops, _) = wire.mutateCalls.single()
        assertEquals(PROVIDER_SETTINGS_NS, ns)
        assertEquals(1, ops.size)
        val set = ops.single() as SettingsPathOpView.Set
        assertEquals(listOf("providers", "acme"), set.path)
        val profile = set.value as JsonObject
        assertEquals("Acme", profile.stringField("displayName"))
        assertEquals("ACME_API_KEY", profile.stringField("apiKeyEnv"))
        assertEquals(ProviderProtocols.ANTHROPIC_MESSAGES, profile.stringField("api"))
        assertEquals(listOf("claude-sonnet-4-5"), profile.modelIds())
        assertEquals(listOf("ACME_API_KEY" to "secret-key"), wire.setCredentials)
    }

    @Test
    fun `saveCustom refuses bad input without touching the wire`() = runTest {
        val wire = FakeWire().apply {
            configurable = listOf(configurable("openai"))
            describeValue = describe(piAiNamespace())
        }
        val m = manager(wire)
        assertEquals(ProviderOutcome.Ok, m.refresh())

        val badRoute = m.saveCustom(
            route = "Bad Route",
            displayName = null,
            baseUrl = "https://relay.example.com",
            api = ProviderProtocols.OPENAI_COMPLETIONS,
            models = listOf(ProviderModelDraft(id = "gpt-5")),
            key = null,
        )
        assertTrue(badRoute is ProviderOutcome.Failed)

        val taken = m.saveCustom(
            route = "openai",
            displayName = null,
            baseUrl = "https://relay.example.com",
            api = ProviderProtocols.OPENAI_COMPLETIONS,
            models = listOf(ProviderModelDraft(id = "gpt-5")),
            key = null,
        )
        assertTrue(taken is ProviderOutcome.Failed)

        val badUrl = m.saveCustom(
            route = "acme",
            displayName = null,
            baseUrl = "https://relay.example.com/v1/chat/completions",
            api = ProviderProtocols.OPENAI_COMPLETIONS,
            models = listOf(ProviderModelDraft(id = "gpt-5")),
            key = null,
        )
        assertTrue(badUrl is ProviderOutcome.Failed)

        val noModels = m.saveCustom(
            route = "acme",
            displayName = null,
            baseUrl = "https://relay.example.com",
            api = ProviderProtocols.OPENAI_COMPLETIONS,
            models = emptyList(),
            key = null,
        )
        assertTrue(noModels is ProviderOutcome.Failed)

        assertTrue(wire.mutateCalls.isEmpty())
        assertTrue(wire.setCredentials.isEmpty())
    }

    @Test
    fun `saveClaim writes only the changed fields`() = runTest {
        val wire = FakeWire().apply {
            configurable = listOf(configurable("openai", active = true))
            describeValue = describe(
                piAiNamespace(
                    value = buildJsonObject {
                        put("providers", buildJsonObject {
                            put("openai", buildJsonObject {
                                put("apiKeyEnv", JsonPrimitive("OPENAI_API_KEY"))
                            })
                        })
                    },
                    user = buildJsonObject {
                        put("providers", buildJsonObject {
                            put("openai", buildJsonObject {
                                put("apiKeyEnv", JsonPrimitive("OPENAI_API_KEY"))
                            })
                        })
                    },
                ),
            )
            keyStates = mapOf("OPENAI_API_KEY" to CredentialInfo(configured = true))
        }
        val m = manager(wire)
        assertEquals(ProviderOutcome.Ok, m.refresh())
        val row = m.state.value.rows.single { it.provider == "openai" }
        val outcome = m.saveClaim(
            row = row,
            api = ProviderProtocols.OPENAI_COMPLETIONS,
            baseUrl = "https://relay.example.com/v1",
            key = null,
            models = null,
        )
        assertEquals(ProviderOutcome.Ok, outcome)
        val (_, ops, _) = wire.mutateCalls.single()
        // apiKeyEnv unchanged, no key given, no models given: only the endpoint moves.
        assertEquals(1, ops.size)
        val set = ops.single() as SettingsPathOpView.Set
        assertEquals(listOf("providers", "openai", "baseURL"), set.path)
        assertTrue(wire.setCredentials.isEmpty())
    }

    @Test
    fun `saveClaim stores a new key under the profile reference`() = runTest {
        val wire = FakeWire().apply {
            configurable = listOf(configurable("openai", active = true))
            describeValue = describe(
                piAiNamespace(
                    user = buildJsonObject {
                        put("providers", buildJsonObject {
                            put("openai", buildJsonObject {
                                put("apiKeyEnv", JsonPrimitive("OPENAI_API_KEY"))
                            })
                        })
                    },
                ),
            )
        }
        val m = manager(wire)
        assertEquals(ProviderOutcome.Ok, m.refresh())
        val row = m.state.value.rows.single { it.provider == "openai" }
        assertEquals(
            ProviderOutcome.Ok,
            m.saveClaim(
                row = row,
                api = ProviderProtocols.OPENAI_COMPLETIONS,
                baseUrl = null,
                key = "new-secret",
                models = null,
            ),
        )
        // The reference did not change, so no settings op at all — only the key moves.
        assertTrue(wire.mutateCalls.isEmpty())
        assertEquals(listOf("OPENAI_API_KEY" to "new-secret"), wire.setCredentials)
    }

    @Test
    fun `a revision conflict re-reads and retries once`() = runTest {
        val wire = FakeWire().apply {
            configurable = listOf(configurable("openai"))
            describeValue = describe(piAiNamespace(revision = 7L))
            mutateAnswers += RpcResult.Err(RpcError(code = SETTINGS_CONFLICT_CODE, message = "conflict"))
        }
        val m = manager(wire)
        assertEquals(ProviderOutcome.Ok, m.refresh())
        val describesBefore = wire.describeCalls
        val outcome = m.saveCustom(
            route = "acme",
            displayName = null,
            baseUrl = "https://relay.example.com",
            api = ProviderProtocols.OPENAI_COMPLETIONS,
            models = listOf(ProviderModelDraft(id = "gpt-5")),
            key = null,
        )
        assertEquals(ProviderOutcome.Ok, outcome)
        assertEquals(2, wire.mutateCalls.size)
        assertTrue(wire.describeCalls > describesBefore)
    }

    @Test
    fun `a second conflict surfaces as Conflict`() = runTest {
        val wire = FakeWire().apply {
            configurable = listOf(configurable("openai"))
            describeValue = describe(piAiNamespace(revision = 7L))
            mutateAnswers += RpcResult.Err(RpcError(code = SETTINGS_CONFLICT_CODE, message = "conflict"))
            mutateAnswers += RpcResult.Err(RpcError(code = SETTINGS_CONFLICT_CODE, message = "conflict"))
        }
        val m = manager(wire)
        assertEquals(ProviderOutcome.Ok, m.refresh())
        val outcome = m.saveCustom(
            route = "acme",
            displayName = null,
            baseUrl = "https://relay.example.com",
            api = ProviderProtocols.OPENAI_COMPLETIONS,
            models = listOf(ProviderModelDraft(id = "gpt-5")),
            key = null,
        )
        assertEquals(ProviderOutcome.Conflict, outcome)
        assertEquals(2, wire.mutateCalls.size)
        assertTrue(wire.setCredentials.isEmpty())
    }

    @Test
    fun `remove unsets the profile and clears the key`() = runTest {
        val wire = FakeWire().apply {
            configurable = listOf(configurable("openai", active = true))
            describeValue = describe(
                piAiNamespace(
                    user = buildJsonObject {
                        put("providers", buildJsonObject {
                            put("openai", buildJsonObject {
                                put("apiKeyEnv", JsonPrimitive("OPENAI_API_KEY"))
                            })
                        })
                    },
                ),
            )
        }
        val m = manager(wire)
        assertEquals(ProviderOutcome.Ok, m.refresh())
        val row = m.state.value.rows.single { it.provider == "openai" }
        assertEquals(ProviderOutcome.Ok, m.remove(row))
        val (_, ops, _) = wire.mutateCalls.single()
        assertEquals(1, ops.size)
        val unset = ops.single() as SettingsPathOpView.Unset
        assertEquals(listOf("providers", "openai"), unset.path)
        assertEquals(listOf("OPENAI_API_KEY"), wire.unsetCredentials)
    }
}
