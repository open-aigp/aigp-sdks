package org.open_aigp.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

class AIGPTest {

    @Test
    void normalizeEventTypeMapsAliases() {
        assertEquals("INJECT_SUCCESS", AIGP.normalizeEventType("governance.policy.delivered"));
        assertEquals("PROMPT_DENIED", AIGP.normalizeEventType("governance.prompt.denied"));
    }

    @Test
    void normalizeEventTypeNormalizesCustomNames() {
        assertEquals("MYPLATFORM_AUDIT_LOGIN", AIGP.normalizeEventType("myplatform.audit.login"));
    }

    @Test
    void createAndValidateEvent() {
        AIGP.CreateEventOptions options = new AIGP.CreateEventOptions();
        options.eventType = "governance.policy.delivered";
        options.eventCategory = "Inject";
        options.agentId = "agent.test";
        options.governanceHash = AIGP.computeGovernanceHash("policy", "sha256");

        AIGP.AIGPEvent event = AIGP.createAIGPEvent(options);
        assertEquals("INJECT_SUCCESS", event.eventType);
        assertEquals("inject", event.eventCategory);
        assertTrue(event.traceId.matches("^[a-f0-9]{32}$"));
        assertEquals("0.10.0", event.specVersion);
        assertEquals(0, AIGP.validateAIGPEvent(event).size());
    }

    @Test
    void computeMerkleGovernanceHashSingleAndMulti() {
        AIGP.Resource policy = new AIGP.Resource("policy", "policy.limits", "Max $10M");

        AIGP.MerkleResult single = AIGP.computeMerkleGovernanceHash(Arrays.asList(policy));
        assertNull(single.merkleTree);
        assertEquals(AIGP.computeGovernanceHash("Max $10M", "sha256"), single.rootHash);

        AIGP.Resource prompt = new AIGP.Resource("prompt", "prompt.system", "You are a trading assistant");
        AIGP.MerkleResult multi = AIGP.computeMerkleGovernanceHash(Arrays.asList(policy, prompt));
        assertNotNull(multi.merkleTree);
        assertEquals(2, multi.merkleTree.leafCount);
        assertNotNull(multi.rootHash);
    }

    @Test
    void inclusionProofsRoundTripAndTamperCheck() {
        AIGP.Resource policy = new AIGP.Resource("policy", "policy.limits", "Max $10M");
        AIGP.Resource prompt = new AIGP.Resource("prompt", "prompt.system", "You are a trading assistant");
        AIGP.Resource tool = new AIGP.Resource("tool", "tool.quote", "allow");

        AIGP.MerkleResult result = AIGP.computeMerkleGovernanceHash(Arrays.asList(policy, prompt, tool), true);
        assertNotNull(result.merkleTree);
        assertNotNull(result.merkleTree.inclusionProofs);
        assertEquals(3, result.merkleTree.inclusionProofs.size());

        AIGP.MerkleInclusionProof proof = result.merkleTree.inclusionProofs.get(0);
        assertTrue(AIGP.verifyInclusionProof(result.rootHash, proof.leafHash, proof.proofPath));
        assertTrue(!AIGP.verifyInclusionProof("00" + result.rootHash.substring(2), proof.leafHash, proof.proofPath));
    }

    @Test
    void signerAndReliableEmitterHelpersWork() throws Exception {
        AIGP.CreateEventOptions options = new AIGP.CreateEventOptions();
        options.eventType = "INJECT_SUCCESS";
        options.eventCategory = "inject";
        options.agentId = "agent.test";
        options.governanceHash = AIGP.computeGovernanceHash("policy", "sha256");
        AIGP.AIGPEvent event = AIGP.createAIGPEvent(options);

        AIGP.EventSigner signer = new AIGP.EventSigner() {
            @Override
            public String algorithm() {
                return "TEST";
            }

            @Override
            public String keyId() {
                return "kid-1";
            }

            @Override
            public byte[] sign(byte[] signingInput) {
                return "signed".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            }
        };

        AIGP.AIGPEvent signed = AIGP.signEventWithSigner(event, signer);
        assertEquals("kid-1", signed.signatureKeyId);
        assertTrue(signed.eventSignature.startsWith("ey"));

        AtomicInteger attempts = new AtomicInteger(0);
        AIGP.ReliableEmitter emitter = new AIGP.ReliableEmitter(
            e -> {
                if (attempts.incrementAndGet() < 2) {
                    throw new RuntimeException("retry");
                }
            },
            new AIGP.RetryPolicy(2, 0L, 0L),
            true
        );
        assertTrue(emitter.emit(signed));
        assertEquals(0, emitter.pendingCount());
        assertEquals(2, attempts.get());
        assertTrue(emitter.emit(signed));
        assertEquals(2, attempts.get());
    }

    @Test
    void computeLeafHashValidatesHashMode() {
        assertThrows(IllegalArgumentException.class, () ->
            AIGP.computeLeafHash("policy", "policy.limits", "Max $10M", "bogus", "")
        );

        AIGP.Resource pointer = new AIGP.Resource("policy", "policy.limits", "");
        pointer.hashMode = "pointer";
        pointer.contentRef = "";
        assertThrows(IllegalArgumentException.class, () ->
            AIGP.computeMerkleGovernanceHash(Arrays.asList(pointer))
        );
    }

    @Test
    void cloudEventsHelpersProduceExpectedMappings() {
        AIGP.CreateEventOptions options = new AIGP.CreateEventOptions();
        options.eventType = "INJECT_SUCCESS";
        options.eventCategory = "inject";
        options.agentId = "agent.test";
        options.orgId = "org.acme";
        options.policyName = "policy.limits";
        options.governanceHash = AIGP.computeGovernanceHash("policy", "sha256");

        AIGP.AIGPEvent event = AIGP.createAIGPEvent(options);
        AIGP.CloudEvent ce = AIGP.wrapAsCloudEvent(event, true);

        assertEquals("org.aigp.v1.inject_success", ce.type);
        assertEquals("aigp://org.acme/agent.test", ce.source);
        assertEquals("policy.limits", ce.subject);

        assertEquals("inject_success", AIGP.eventTypeFromCeType(ce.type));

        java.util.Map<String, String> headers = AIGP.buildCEHeaders(event, "ce-");
        assertEquals("org.aigp.v1.inject_success", headers.get("ce-type"));
        assertEquals("agent.test", headers.get("ce-aigpagentid"));
    }

    @Test
    void createRejectsEmptyGovernanceHash() {
        AIGP.CreateEventOptions options = new AIGP.CreateEventOptions();
        options.eventType = "AGENT_REGISTERED";
        options.eventCategory = "agent-lifecycle";
        options.agentId = "agent.test";
        options.governanceHash = "";
        options.traceId = "trace-550e8400-e29b-41d4-a716-446655440000";

        assertThrows(IllegalArgumentException.class, () -> AIGP.createAIGPEvent(options));
    }

    @Test
    void validatorRequiresW3CTraceWhenSpanPresent() {
        AIGP.CreateEventOptions options = new AIGP.CreateEventOptions();
        options.eventType = "INJECT_SUCCESS";
        options.eventCategory = "inject";
        options.agentId = "agent.test";
        options.governanceHash = "abc";
        options.traceId = "trace-550e8400-e29b-41d4-a716-446655440000";
        options.spanId = "00f067aa0ba902b7";

        AIGP.AIGPEvent event = AIGP.createAIGPEvent(options);
        List<String> errors = AIGP.validateAIGPEvent(event);
        assertTrue(errors.stream().anyMatch(s -> s.contains("trace_id must be 32-char lowercase hex when span_id is present")));
    }

    @Test
    void conformanceFixtures() throws Exception {
        Path fixture = Path.of("..", "conformance", "validation-fixtures.tsv");
        List<String> lines = Files.readAllLines(fixture);
        String[] header = lines.get(0).split("\t", -1);
        for (int i = 1; i < lines.size(); i++) {
            String line = lines.get(i).trim();
            if (line.isEmpty()) {
                continue;
            }
            String[] parts = line.split("\t", -1);
            if (parts.length != header.length) {
                throw new IllegalStateException("Invalid fixture row: " + line);
            }
            Map<String, String> row = new LinkedHashMap<String, String>();
            for (int j = 0; j < header.length; j++) {
                row.put(header[j], parts[j]);
            }

            AIGP.CreateEventOptions options = new AIGP.CreateEventOptions();
            options.eventType = row.get("event_type");
            options.eventCategory = row.get("event_category");
            options.agentId = "agent.test";
            options.traceId = row.get("trace_id");
            options.spanId = row.get("span_id");
            options.governanceHash = row.get("governance_hash");
            options.sequenceNumber = Long.parseLong(row.get("sequence_number"));
            options.causalityRef = row.get("causality_ref");
            boolean isValid;
            try {
                AIGP.AIGPEvent event = AIGP.createAIGPEvent(options);
                event.sequenceNumber = Long.parseLong(row.get("sequence_number"));
                event.causalityRef = row.get("causality_ref");
                isValid = AIGP.validateAIGPEvent(event).isEmpty();
            } catch (IllegalArgumentException ex) {
                isValid = false;
            }
            boolean expectValid = "true".equals(row.get("expect_valid"));
            assertEquals(expectValid, isValid, "fixture failed: " + row.get("case_id"));
        }
    }
}
