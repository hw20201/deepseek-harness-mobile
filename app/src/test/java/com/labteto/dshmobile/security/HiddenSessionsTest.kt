package com.labteto.dshmobile.security

import com.labteto.dshmobile.data.SessionRow
import com.labteto.dshmobile.ui.screens.main.splitDrawerSessions
import org.junit.Assert.assertEquals
import org.junit.Test

class HiddenSessionsTest {

    private fun row(id: String, blank: Boolean = false) = SessionRow(
        sessionId = id,
        title = id,
        running = false,
        blank = blank,
        parentSessionId = null,
        origin = null,
        cwd = null,
        agentPreset = null,
        updatedAt = 0L,
        pendingInteraction = null,
    )

    @Test
    fun `hidden sessions leave the listable bucket for the hidden one`() {
        val split = splitDrawerSessions(
            sessions = listOf(row("dev-1"), row("fish-1"), row("fish-2")),
            hiddenIds = setOf("fish-1", "fish-2"),
            archivedIds = emptySet(),
        )
        assertEquals(listOf("dev-1"), split.listable.map { it.sessionId })
        assertEquals(listOf("fish-1", "fish-2"), split.hidden.map { it.sessionId })
        assertEquals(emptyList<String>(), split.archived.map { it.sessionId })
    }

    @Test
    fun `archived and hidden are separate buckets`() {
        val split = splitDrawerSessions(
            sessions = listOf(row("dev-1"), row("old-1"), row("fish-1")),
            hiddenIds = setOf("fish-1"),
            archivedIds = setOf("old-1"),
        )
        assertEquals(listOf("dev-1"), split.listable.map { it.sessionId })
        assertEquals(listOf("old-1"), split.archived.map { it.sessionId })
        assertEquals(listOf("fish-1"), split.hidden.map { it.sessionId })
    }

    @Test
    fun `blank sessions are listable nowhere unless hidden or archived`() {
        val split = splitDrawerSessions(
            sessions = listOf(row("blank-1", blank = true), row("blank-2", blank = true)),
            hiddenIds = setOf("blank-2"),
            archivedIds = emptySet(),
        )
        assertEquals(emptyList<String>(), split.listable.map { it.sessionId })
        assertEquals(listOf("blank-2"), split.hidden.map { it.sessionId })
    }
}
