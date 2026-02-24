package org.open_aigp.sdk

import java.io.File
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class AIGPTest {

    @Test
    fun normalizeEventTypeMapsAliases() {
        assertEquals("INJECT_SUCCESS", normalizeEventType("governance.policy.delivered"))
        assertEquals("PROMPT_DENIED", normalizeEventType("governance.prompt.denied"))
    }

    @Test
    fun normalizeEventTypeNormalizesCustomNames() {
        assertEquals("MYPLATFORM_AUDIT_LOGIN", normalizeEventType("myplatform.audit.login"))
    }

    @Test
    fun createAndValidateEvent() {
        val event = createAIGPEvent(
            CreateEventOptions(
                eventType = "governance.policy.delivered",
                eventCategory = "Inject",
                agentId = "agent.test",
                governanceHash = computeGovernanceHash("policy", "sha256"),
            )
        )

        assertEquals("INJECT_SUCCESS", event.eventType)
        assertEquals("inject", event.eventCategory)
        assertTrue(event.traceId.matches(Regex("^[a-f0-9]{32}$")))
        assertEquals("0.10.0", event.specVersion)
        assertEquals(0, validateAIGPEvent(event).size)
    }

    @Test
    fun computeMerkleGovernanceHashSingleAndMulti() {
        val single = computeMerkleGovernanceHash(
            listOf(Resource("policy", "policy.limits", "Max $10M"))
        )
        assertNull(single.merkleTree)
        assertEquals(computeGovernanceHash("Max $10M", "sha256"), single.rootHash)

        val multi = computeMerkleGovernanceHash(
            listOf(
                Resource("policy", "policy.limits", "Max $10M"),
                Resource("prompt", "prompt.system", "You are a trading assistant"),
            )
        )
        assertNotNull(multi.merkleTree)
        assertEquals(2, multi.merkleTree.leafCount)
    }

    @Test
    fun inclusionProofsRoundTripAndTamperCheck() {
        val result = computeMerkleGovernanceHash(
            listOf(
                Resource("policy", "policy.limits", "Max $10M"),
                Resource("prompt", "prompt.system", "You are a trading assistant"),
                Resource("tool", "tool.quote", "allow"),
            ),
            includeInclusionProofs = true,
        )
        val tree = requireNotNull(result.merkleTree)
        val proofs = requireNotNull(tree.inclusionProofs)
        assertEquals(3, proofs.size)
        assertTrue(verifyInclusionProof(result.rootHash, proofs[0].leafHash, proofs[0].proofPath))
        assertTrue(!verifyInclusionProof("00${result.rootHash.drop(2)}", proofs[0].leafHash, proofs[0].proofPath))
    }

    @Test
    fun signerAndReliableEmitterHelpersWork() {
        val event = createAIGPEvent(
            CreateEventOptions(
                eventType = "INJECT_SUCCESS",
                eventCategory = "inject",
                agentId = "agent.test",
                governanceHash = computeGovernanceHash("policy", "sha256"),
            )
        )

        val signer = object : EventSigner {
            override val algorithm: String = "TEST"
            override val keyId: String = "kid-1"
            override fun sign(signingInput: ByteArray): ByteArray = "signed".toByteArray()
        }

        val signed = signEventWithSigner(event, signer)
        assertEquals("kid-1", signed.signatureKeyId)
        assertTrue(signed.eventSignature.startsWith("ey"))

        val attempts = AtomicInteger(0)
        val emitter = ReliableEmitter(
            sender = {
                if (attempts.incrementAndGet() < 2) {
                    error("retry")
                }
            },
            retryPolicy = RetryPolicy(maxAttempts = 2, baseDelayMs = 0, maxDelayMs = 0),
            idempotent = true,
            sleepFn = {},
        )
        assertTrue(emitter.emit(signed))
        assertEquals(0, emitter.pendingCount)
        assertEquals(2, attempts.get())
        assertTrue(emitter.emit(signed))
        assertEquals(2, attempts.get())
    }

    @Test
    fun computeLeafHashValidatesHashMode() {
        assertFailsWith<IllegalArgumentException> {
            computeLeafHash("policy", "policy.limits", "Max $10M", "bogus", "")
        }

        assertFailsWith<IllegalArgumentException> {
            computeMerkleGovernanceHash(
                listOf(Resource("policy", "policy.limits", "", hashMode = "pointer", contentRef = ""))
            )
        }
    }

    @Test
    fun cloudEventsHelpersProduceExpectedMappings() {
        val event = createAIGPEvent(
            CreateEventOptions(
                eventType = "INJECT_SUCCESS",
                eventCategory = "inject",
                agentId = "agent.test",
                orgId = "org.acme",
                policyName = "policy.limits",
                governanceHash = computeGovernanceHash("policy", "sha256"),
            )
        )

        val ce = wrapAsCloudEvent(event)
        assertEquals("org.aigp.v1.inject_success", ce.type)
        assertEquals("aigp://org.acme/agent.test", ce.source)
        assertEquals("policy.limits", ce.subject)

        val headers = buildCEHeaders(event)
        assertEquals("org.aigp.v1.inject_success", headers["ce-type"])
        assertEquals("agent.test", headers["ce-aigpagentid"])
    }

    @Test
    fun createRejectsEmptyGovernanceHash() {
        assertFailsWith<IllegalArgumentException> {
            createAIGPEvent(
                CreateEventOptions(
                    eventType = "AGENT_REGISTERED",
                    eventCategory = "agent-lifecycle",
                    agentId = "agent.test",
                    governanceHash = "",
                    traceId = "trace-550e8400-e29b-41d4-a716-446655440000",
                )
            )
        }
    }

    @Test
    fun validatorRequiresW3CTraceWhenSpanPresent() {
        val event = createAIGPEvent(
            CreateEventOptions(
                eventType = "INJECT_SUCCESS",
                eventCategory = "inject",
                agentId = "agent.test",
                governanceHash = "abc",
                traceId = "trace-550e8400-e29b-41d4-a716-446655440000",
                spanId = "00f067aa0ba902b7",
            )
        )
        val errors = validateAIGPEvent(event)
        assertTrue(errors.any { it.contains("trace_id must be 32-char lowercase hex when span_id is present") })
    }

    @Test
    fun conformanceFixtures() {
        val fixture = File("../conformance/validation-fixtures.tsv")
        val lines = fixture.readLines()
        val header = lines.first().split('\t')
        for (line in lines.drop(1)) {
            val trimmed = line.trim()
            if (trimmed.isEmpty()) {
                continue
            }
            val parts = trimmed.split('\t')
            require(parts.size == header.size) { "Invalid fixture row: $trimmed" }
            val row = header.zip(parts).toMap()

            val isValid = try {
                val event = createAIGPEvent(
                    CreateEventOptions(
                        eventType = row.getValue("event_type"),
                        eventCategory = row.getValue("event_category"),
                        agentId = "agent.test",
                        traceId = row.getValue("trace_id"),
                        spanId = row.getValue("span_id"),
                        governanceHash = row.getValue("governance_hash"),
                        sequenceNumber = row.getValue("sequence_number").toLong(),
                        causalityRef = row.getValue("causality_ref"),
                    )
                ).copy(
                    sequenceNumber = row.getValue("sequence_number").toLong(),
                    causalityRef = row.getValue("causality_ref"),
                )
                validateAIGPEvent(event).isEmpty()
            } catch (_: IllegalArgumentException) {
                false
            }
            val expectValid = row.getValue("expect_valid") == "true"
            assertEquals(expectValid, isValid, "fixture failed: ${row.getValue("case_id")}")
        }
    }
}
