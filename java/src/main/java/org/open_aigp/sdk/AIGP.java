package org.open_aigp.sdk;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * AIGP Java SDK core helpers.
 */
public final class AIGP {

    public static final String VERSION = "0.1.0";

    public static final String CE_SPECVERSION = "1.0";
    public static final String AIGP_TYPE_PREFIX = "org.aigp.v1.";
    public static final String AIGP_SOURCE_SCHEME = "aigp://";
    public static final String AIGP_DATA_SCHEMA = "https://open-aigp.org/schema/aigp-event.schema.json";

    private static final Pattern RESOURCE_TYPE_PATTERN = Pattern.compile("^[a-z][a-z0-9]*(-[a-z0-9]+)*$");
    private static final Pattern EVENT_TYPE_PATTERN = Pattern.compile("^[A-Z][A-Z0-9_]*$");
    private static final Pattern TRACE_ID_OTEL_PATTERN = Pattern.compile("^[a-f0-9]{32}$");
    private static final Pattern TRACE_ID_UUID_V4_PATTERN = Pattern.compile("(?i)^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$");
    private static final Pattern TRACE_ID_PREFIXED_UUID_V4_PATTERN = Pattern.compile("(?i)^(trace|req)-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$");

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final DateTimeFormatter RFC3339_MILLIS_UTC = DateTimeFormatter
        .ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
        .withZone(ZoneOffset.UTC);
    private static final Map<String, Long> SEQUENCE_COUNTERS = new HashMap<String, Long>();

    private static final Map<String, String> EVENT_TYPE_ALIASES;

    static {
        Map<String, String> aliases = new HashMap<String, String>();
        aliases.put("governance.policy.delivered", "INJECT_SUCCESS");
        aliases.put("governance.policy.denied", "INJECT_DENIED");
        aliases.put("governance.prompt.delivered", "PROMPT_USED");
        aliases.put("governance.prompt.denied", "PROMPT_DENIED");
        aliases.put("governance.policy.violation", "POLICY_VIOLATION");
        aliases.put("governance.a2a.call", "A2A_CALL");
        aliases.put("governance.tool.invoked", "TOOL_INVOKED");
        aliases.put("governance.tool.denied", "TOOL_DENIED");
        aliases.put("governance.boundary.unverified", "UNVERIFIED_BOUNDARY");
        aliases.put("governance.inference.started", "INFERENCE_STARTED");
        aliases.put("governance.inference.completed", "INFERENCE_COMPLETED");
        aliases.put("governance.inference.blocked", "INFERENCE_BLOCKED");
        aliases.put("governance.model.loaded", "MODEL_LOADED");
        aliases.put("governance.model.switched", "MODEL_SWITCHED");
        aliases.put("governance.memory.read", "MEMORY_READ");
        aliases.put("governance.memory.written", "MEMORY_WRITTEN");
        aliases.put("governance.proof", "GOVERNANCE_PROOF");
        aliases.put("governance.proof.delivered", "GOVERNANCE_PROOF");
        EVENT_TYPE_ALIASES = Collections.unmodifiableMap(aliases);
    }

    public interface EventSigner {
        String algorithm();
        String keyId();
        byte[] sign(byte[] signingInput) throws Exception;
    }

    public interface EventSender {
        void send(AIGPEvent event) throws Exception;
    }

    public static final class RetryPolicy {
        public final int maxAttempts;
        public final long baseDelayMs;
        public final long maxDelayMs;

        public RetryPolicy() {
            this(3, 100L, 2000L);
        }

        public RetryPolicy(int maxAttempts, long baseDelayMs, long maxDelayMs) {
            this.maxAttempts = maxAttempts > 0 ? maxAttempts : 3;
            this.baseDelayMs = baseDelayMs >= 0 ? baseDelayMs : 100L;
            this.maxDelayMs = maxDelayMs >= 0 ? maxDelayMs : 2000L;
        }

        public long delayForAttempt(int attempt) {
            int safeAttempt = Math.max(1, attempt);
            long delay = baseDelayMs * (1L << Math.max(0, safeAttempt - 1));
            return Math.min(delay, maxDelayMs);
        }
    }

    public static final class FlushResult {
        public final int delivered;
        public final int pending;

        public FlushResult(int delivered, int pending) {
            this.delivered = delivered;
            this.pending = pending;
        }
    }

    public static final class ReliableEmitter {
        private final EventSender sender;
        private final RetryPolicy retryPolicy;
        private final boolean idempotent;
        private final Set<String> deliveredIds;
        private final List<AIGPEvent> failedEvents;

        public ReliableEmitter(EventSender sender) {
            this(sender, new RetryPolicy(), true);
        }

        public ReliableEmitter(EventSender sender, RetryPolicy retryPolicy, boolean idempotent) {
            if (sender == null) {
                throw new IllegalArgumentException("sender is required");
            }
            this.sender = sender;
            this.retryPolicy = retryPolicy == null ? new RetryPolicy() : retryPolicy;
            this.idempotent = idempotent;
            this.deliveredIds = new HashSet<String>();
            this.failedEvents = new ArrayList<AIGPEvent>();
        }

        public synchronized int pendingCount() {
            return failedEvents.size();
        }

        public synchronized boolean emit(AIGPEvent event) {
            String eventId = event == null ? "" : safeTrim(event.eventId);
            if (idempotent && !isBlank(eventId) && deliveredIds.contains(eventId)) {
                return true;
            }

            int attempts = Math.max(1, retryPolicy.maxAttempts);
            for (int attempt = 1; attempt <= attempts; attempt++) {
                try {
                    sender.send(event);
                    if (!isBlank(eventId)) {
                        deliveredIds.add(eventId);
                    }
                    return true;
                } catch (Exception ignored) {
                    if (attempt < attempts) {
                        sleepQuietly(retryPolicy.delayForAttempt(attempt));
                    }
                }
            }

            failedEvents.add(copyEvent(event));
            return false;
        }

        public synchronized FlushResult flushFailed(int maxItems) {
            int limit = maxItems > 0 ? maxItems : 1000;
            int delivered = 0;
            List<AIGPEvent> remaining = new ArrayList<AIGPEvent>();
            for (int i = 0; i < failedEvents.size(); i++) {
                AIGPEvent event = failedEvents.get(i);
                if (i >= limit) {
                    remaining.add(event);
                    continue;
                }
                if (emit(event)) {
                    delivered += 1;
                } else {
                    remaining.add(event);
                }
            }
            failedEvents.clear();
            failedEvents.addAll(remaining);
            return new FlushResult(delivered, failedEvents.size());
        }
    }

    private AIGP() {
    }

    public static final class MerkleLeaf {
        public final String resourceType;
        public final String resourceName;
        public final String hash;
        public final String hashMode;
        public final String contentRef;

        public MerkleLeaf(String resourceType, String resourceName, String hash, String hashMode, String contentRef) {
            this.resourceType = resourceType;
            this.resourceName = resourceName;
            this.hash = hash;
            this.hashMode = hashMode;
            this.contentRef = contentRef;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> out = new LinkedHashMap<String, Object>();
            out.put("resource_type", resourceType);
            out.put("resource_name", resourceName);
            out.put("hash", hash);
            if (!isBlank(hashMode) && !"content".equals(hashMode)) {
                out.put("hash_mode", hashMode);
            }
            if (!isBlank(contentRef)) {
                out.put("content_ref", contentRef);
            }
            return out;
        }
    }

    public static final class MerkleProofStep {
        public final String siblingHash;
        public final String siblingPosition;

        public MerkleProofStep(String siblingHash, String siblingPosition) {
            this.siblingHash = siblingHash;
            this.siblingPosition = siblingPosition;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> out = new LinkedHashMap<String, Object>();
            out.put("sibling_hash", siblingHash);
            out.put("sibling_position", siblingPosition);
            return out;
        }
    }

    public static final class MerkleInclusionProof {
        public final String leafHash;
        public final List<MerkleProofStep> proofPath;

        public MerkleInclusionProof(String leafHash, List<MerkleProofStep> proofPath) {
            this.leafHash = leafHash;
            this.proofPath = proofPath;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> out = new LinkedHashMap<String, Object>();
            out.put("leaf_hash", leafHash);
            List<Map<String, Object>> mapped = new ArrayList<Map<String, Object>>();
            if (proofPath != null) {
                for (MerkleProofStep step : proofPath) {
                    mapped.add(step.toMap());
                }
            }
            out.put("proof_path", mapped);
            return out;
        }
    }

    public static final class GovernanceMerkleTree {
        public final String algorithm;
        public final int leafCount;
        public final List<MerkleLeaf> leaves;
        public final List<MerkleInclusionProof> inclusionProofs;

        public GovernanceMerkleTree(String algorithm, int leafCount, List<MerkleLeaf> leaves) {
            this(algorithm, leafCount, leaves, null);
        }

        public GovernanceMerkleTree(String algorithm, int leafCount, List<MerkleLeaf> leaves, List<MerkleInclusionProof> inclusionProofs) {
            this.algorithm = algorithm;
            this.leafCount = leafCount;
            this.leaves = leaves;
            this.inclusionProofs = inclusionProofs;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> out = new LinkedHashMap<String, Object>();
            out.put("algorithm", algorithm);
            out.put("leaf_count", leafCount);
            List<Map<String, Object>> mapped = new ArrayList<Map<String, Object>>();
            for (MerkleLeaf leaf : leaves) {
                mapped.add(leaf.toMap());
            }
            out.put("leaves", mapped);
            if (inclusionProofs != null && !inclusionProofs.isEmpty()) {
                List<Map<String, Object>> mappedProofs = new ArrayList<Map<String, Object>>();
                for (MerkleInclusionProof proof : inclusionProofs) {
                    mappedProofs.add(proof.toMap());
                }
                out.put("inclusion_proofs", mappedProofs);
            }
            return out;
        }
    }

    public static final class MerkleResult {
        public final String rootHash;
        public final GovernanceMerkleTree merkleTree;

        public MerkleResult(String rootHash, GovernanceMerkleTree merkleTree) {
            this.rootHash = rootHash;
            this.merkleTree = merkleTree;
        }
    }

    public static final class Resource {
        public String resourceType;
        public String resourceName;
        public String content;
        public String hashMode;
        public String contentRef;

        public Resource(String resourceType, String resourceName, String content) {
            this.resourceType = resourceType;
            this.resourceName = resourceName;
            this.content = content;
            this.hashMode = "content";
            this.contentRef = "";
        }

        public Resource(String resourceType, String resourceName, String content, String hashMode, String contentRef) {
            this.resourceType = resourceType;
            this.resourceName = resourceName;
            this.content = content;
            this.hashMode = hashMode;
            this.contentRef = contentRef;
        }
    }

    public static final class CreateEventOptions {
        public String eventType;
        public String eventCategory;
        public String agentId;
        public String traceId;
        public String governanceHash;
        public String spanId;
        public String parentSpanId;
        public String traceFlags;
        public String agentName;
        public String orgId;
        public String orgName;
        public String policyId;
        public String policyName;
        public int policyVersion;
        public String promptId;
        public String promptName;
        public int promptVersion;
        public String hashType;
        public String dataClassification;
        public boolean templateRendered;
        public String denialReason;
        public String violationType;
        public String severity;
        public String sourceIp;
        public String requestMethod;
        public String requestPath;
        public String queryHash;
        public String previousHash;
        public Map<String, Object> annotations;
        public String eventSignature;
        public String signatureKeyId;
        public long sequenceNumber;
        public String causalityRef;
        public String specVersion;
        public GovernanceMerkleTree governanceMerkleTree;
    }

    public static final class AIGPEvent {
        public String eventId;
        public String eventType;
        public String eventCategory;
        public String eventTime;
        public String agentId;
        public String governanceHash;
        public String traceId;
        public String spanId;
        public String parentSpanId;
        public String traceFlags;
        public String agentName;
        public String orgId;
        public String orgName;
        public String policyId;
        public String policyName;
        public int policyVersion;
        public String promptId;
        public String promptName;
        public int promptVersion;
        public String hashType;
        public String dataClassification;
        public boolean templateRendered;
        public String denialReason;
        public String violationType;
        public String severity;
        public String sourceIp;
        public String requestMethod;
        public String requestPath;
        public String queryHash;
        public String previousHash;
        public Map<String, Object> annotations;
        public String eventSignature;
        public String signatureKeyId;
        public long sequenceNumber;
        public String causalityRef;
        public String specVersion;
        public GovernanceMerkleTree governanceMerkleTree;

        public Map<String, Object> toMap() {
            Map<String, Object> out = new LinkedHashMap<String, Object>();
            out.put("event_id", eventId);
            out.put("event_type", eventType);
            out.put("event_category", eventCategory);
            out.put("event_time", eventTime);
            out.put("agent_id", agentId);
            out.put("governance_hash", governanceHash);
            out.put("trace_id", traceId);
            out.put("span_id", spanId);
            out.put("parent_span_id", parentSpanId);
            out.put("trace_flags", traceFlags);
            out.put("agent_name", agentName);
            out.put("org_id", orgId);
            out.put("org_name", orgName);
            out.put("policy_id", policyId);
            out.put("policy_name", policyName);
            out.put("policy_version", policyVersion);
            out.put("prompt_id", promptId);
            out.put("prompt_name", promptName);
            out.put("prompt_version", promptVersion);
            out.put("hash_type", hashType);
            out.put("data_classification", dataClassification);
            out.put("template_rendered", templateRendered);
            out.put("denial_reason", denialReason);
            out.put("violation_type", violationType);
            out.put("severity", severity);
            out.put("source_ip", sourceIp);
            out.put("request_method", requestMethod);
            out.put("request_path", requestPath);
            out.put("query_hash", queryHash);
            out.put("previous_hash", previousHash);
            out.put("annotations", annotations == null ? Collections.<String, Object>emptyMap() : annotations);
            out.put("event_signature", eventSignature);
            out.put("signature_key_id", signatureKeyId);
            out.put("sequence_number", sequenceNumber);
            out.put("causality_ref", causalityRef);
            out.put("spec_version", specVersion);
            if (governanceMerkleTree != null) {
                out.put("governance_merkle_tree", governanceMerkleTree.toMap());
            }
            return out;
        }
    }

    public static final class CloudEvent {
        public String specversion;
        public String id;
        public String type;
        public String source;
        public String datacontenttype;
        public String time;
        public String dataschema;
        public String subject;
        public String aigpagentid;
        public String aigporgid;
        public String aigpcategory;
        public String aigpclassification;
        public String aigpseverity;
        public String aigphashtype;
        public AIGPEvent data;

        public Map<String, Object> toMap() {
            Map<String, Object> out = new LinkedHashMap<String, Object>();
            out.put("specversion", specversion);
            out.put("id", id);
            out.put("type", type);
            out.put("source", source);
            out.put("datacontenttype", datacontenttype);
            if (!isBlank(time)) {
                out.put("time", time);
            }
            if (!isBlank(dataschema)) {
                out.put("dataschema", dataschema);
            }
            if (!isBlank(subject)) {
                out.put("subject", subject);
            }
            out.put("aigpagentid", aigpagentid);
            if (!isBlank(aigporgid)) {
                out.put("aigporgid", aigporgid);
            }
            if (!isBlank(aigpcategory)) {
                out.put("aigpcategory", aigpcategory);
            }
            if (!isBlank(aigpclassification)) {
                out.put("aigpclassification", aigpclassification);
            }
            if (!isBlank(aigpseverity)) {
                out.put("aigpseverity", aigpseverity);
            }
            if (!isBlank(aigphashtype)) {
                out.put("aigphashtype", aigphashtype);
            }
            out.put("data", data == null ? null : data.toMap());
            return out;
        }
    }

    public static String normalizeEventType(String eventType) {
        String raw = safeTrim(eventType);
        if (isBlank(raw)) {
            throw new IllegalArgumentException("event_type must be a non-empty string");
        }

        String mapped = EVENT_TYPE_ALIASES.containsKey(raw) ? EVENT_TYPE_ALIASES.get(raw) : raw;
        if (EVENT_TYPE_PATTERN.matcher(mapped).matches()) {
            return mapped;
        }

        String normalized = mapped.replaceAll("[^A-Za-z0-9]+", "_").replaceAll("^_+|_+$", "").toUpperCase(Locale.ROOT);
        if (isBlank(normalized) || !EVENT_TYPE_PATTERN.matcher(normalized).matches()) {
            throw new IllegalArgumentException("event_type cannot be normalized to valid UPPER_SNAKE_CASE: " + eventType);
        }
        return normalized;
    }

    public static String normalizeEventCategory(String eventCategory) {
        String raw = safeTrim(eventCategory).toLowerCase(Locale.ROOT);
        if (isBlank(raw)) {
            return "governance";
        }
        String normalized = raw.replace("_", "-").replaceAll("[^a-z0-9-]+", "-").replaceAll("^-+|-+$", "");
        return isBlank(normalized) ? "governance" : normalized;
    }

    public static String computeGovernanceHash(String content) {
        return computeGovernanceHash(content, "sha256");
    }

    public static String computeGovernanceHash(String content, String algorithm) {
        String normalizedAlgorithm = isBlank(algorithm) ? "sha256" : algorithm.toLowerCase(Locale.ROOT);
        String digestAlgorithm;
        if ("sha256".equals(normalizedAlgorithm)) {
            digestAlgorithm = "SHA-256";
        } else if ("sha384".equals(normalizedAlgorithm)) {
            digestAlgorithm = "SHA-384";
        } else if ("sha512".equals(normalizedAlgorithm)) {
            digestAlgorithm = "SHA-512";
        } else {
            throw new IllegalArgumentException("Unsupported hash algorithm: " + algorithm);
        }
        return digestHex(digestAlgorithm, content == null ? "" : content);
    }

    public static String computeLeafHash(
        String resourceType,
        String resourceName,
        String content,
        String hashMode,
        String contentRef
    ) {
        if (isBlank(resourceType) || !RESOURCE_TYPE_PATTERN.matcher(resourceType).matches()) {
            throw new IllegalArgumentException("Invalid resource_type: " + resourceType);
        }

        String normalizedHashMode = isBlank(hashMode) ? "content" : hashMode;
        if (!"content".equals(normalizedHashMode) && !"pointer".equals(normalizedHashMode)) {
            throw new IllegalArgumentException("Unsupported hash_mode: " + hashMode + " (expected 'content' or 'pointer')");
        }

        String hashable = content == null ? "" : content;
        if ("pointer".equals(normalizedHashMode)) {
            if (isBlank(contentRef)) {
                throw new IllegalArgumentException("content_ref is required when hash_mode='pointer'");
            }
            hashable = contentRef;
        }

        String prefixed = resourceType + ":" + nullToEmpty(resourceName) + ":" + hashable;
        return computeGovernanceHash(prefixed, "sha256");
    }

    public static MerkleResult computeMerkleGovernanceHash(List<Resource> resources) {
        return computeMerkleGovernanceHash(resources, false);
    }

    public static MerkleResult computeMerkleGovernanceHash(List<Resource> resources, boolean includeInclusionProofs) {
        if (resources == null || resources.isEmpty()) {
            throw new IllegalArgumentException("At least one resource is required");
        }

        if (resources.size() == 1) {
            Resource single = resources.get(0);
            String hashMode = isBlank(single.hashMode) ? "content" : single.hashMode;
            if (!"content".equals(hashMode) && !"pointer".equals(hashMode)) {
                throw new IllegalArgumentException("Unsupported hash_mode: " + hashMode + " (expected 'content' or 'pointer')");
            }
            if ("pointer".equals(hashMode)) {
                if (isBlank(single.contentRef)) {
                    throw new IllegalArgumentException("content_ref is required when hash_mode='pointer'");
                }
                return new MerkleResult(computeGovernanceHash(single.contentRef, "sha256"), null);
            }
            return new MerkleResult(computeGovernanceHash(single.content, "sha256"), null);
        }

        List<MerkleLeaf> leaves = new ArrayList<MerkleLeaf>();
        for (Resource resource : resources) {
            String hashMode = isBlank(resource.hashMode) ? "content" : resource.hashMode;
            String hash = computeLeafHash(resource.resourceType, resource.resourceName, resource.content, hashMode, resource.contentRef);
            String leafHashMode = "content".equals(hashMode) ? null : hashMode;
            String leafContentRef = isBlank(resource.contentRef) ? null : resource.contentRef;
            leaves.add(new MerkleLeaf(resource.resourceType, resource.resourceName, hash, leafHashMode, leafContentRef));
        }

        Collections.sort(leaves, new Comparator<MerkleLeaf>() {
            @Override
            public int compare(MerkleLeaf a, MerkleLeaf b) {
                return a.hash.compareTo(b.hash);
            }
        });

        List<String> hashes = new ArrayList<String>();
        for (MerkleLeaf leaf : leaves) {
            hashes.add(leaf.hash);
        }

        String root = computeMerkleRoot(hashes);
        List<MerkleInclusionProof> proofs = includeInclusionProofs ? buildInclusionProofs(leaves) : null;
        GovernanceMerkleTree tree = new GovernanceMerkleTree("sha256", leaves.size(), leaves, proofs);
        return new MerkleResult(root, tree);
    }

    public static List<MerkleInclusionProof> buildInclusionProofs(List<MerkleLeaf> leaves) {
        if (leaves == null || leaves.isEmpty()) {
            return new ArrayList<MerkleInclusionProof>();
        }

        class Node {
            final String hash;
            final List<Integer> leafIndexes;

            Node(String hash, List<Integer> leafIndexes) {
                this.hash = hash;
                this.leafIndexes = leafIndexes;
            }
        }

        List<List<MerkleProofStep>> proofPaths = new ArrayList<List<MerkleProofStep>>(leaves.size());
        for (int i = 0; i < leaves.size(); i++) {
            proofPaths.add(new ArrayList<MerkleProofStep>());
        }

        List<Node> nodes = new ArrayList<Node>(leaves.size());
        for (int i = 0; i < leaves.size(); i++) {
            List<Integer> indexes = new ArrayList<Integer>(1);
            indexes.add(i);
            nodes.add(new Node(leaves.get(i).hash, indexes));
        }

        while (nodes.size() > 1) {
            List<Node> next = new ArrayList<Node>((nodes.size() + 1) / 2);
            for (int i = 0; i < nodes.size(); i += 2) {
                if (i + 1 >= nodes.size()) {
                    next.add(nodes.get(i));
                    continue;
                }

                Node left = nodes.get(i);
                Node right = nodes.get(i + 1);
                for (Integer leafIndex : left.leafIndexes) {
                    proofPaths.get(leafIndex).add(new MerkleProofStep(right.hash, "right"));
                }
                for (Integer leafIndex : right.leafIndexes) {
                    proofPaths.get(leafIndex).add(new MerkleProofStep(left.hash, "left"));
                }

                List<Integer> merged = new ArrayList<Integer>(left.leafIndexes.size() + right.leafIndexes.size());
                merged.addAll(left.leafIndexes);
                merged.addAll(right.leafIndexes);
                next.add(new Node(computeGovernanceHash(left.hash + right.hash, "sha256"), merged));
            }
            nodes = next;
        }

        List<MerkleInclusionProof> proofs = new ArrayList<MerkleInclusionProof>(leaves.size());
        for (int i = 0; i < leaves.size(); i++) {
            proofs.add(new MerkleInclusionProof(leaves.get(i).hash, proofPaths.get(i)));
        }
        return proofs;
    }

    public static boolean verifyInclusionProof(String rootHash, String leafHash, List<MerkleProofStep> proofPath) {
        String current = safeTrim(leafHash);
        String expected = safeTrim(rootHash);
        if (isBlank(current) || isBlank(expected)) {
            return false;
        }

        List<MerkleProofStep> safePath = proofPath == null ? Collections.<MerkleProofStep>emptyList() : proofPath;
        for (MerkleProofStep step : safePath) {
            if (step == null || isBlank(step.siblingHash)) {
                return false;
            }
            if ("left".equals(step.siblingPosition)) {
                current = computeGovernanceHash(step.siblingHash + current, "sha256");
            } else if ("right".equals(step.siblingPosition)) {
                current = computeGovernanceHash(current + step.siblingHash, "sha256");
            } else {
                throw new IllegalArgumentException(
                    "Invalid sibling_position in proof step: " + step.siblingPosition + " (expected 'left' or 'right')"
                );
            }
        }

        return current.equals(expected);
    }

    public static AIGPEvent signEventWithSigner(AIGPEvent event, EventSigner signer) {
        if (event == null) {
            throw new IllegalArgumentException("event is required");
        }
        if (signer == null) {
            throw new IllegalArgumentException("signer is required");
        }

        Map<String, Object> header = new LinkedHashMap<String, Object>();
        header.put("alg", isBlank(signer.algorithm()) ? "ES256" : signer.algorithm());
        header.put("typ", "JWT");
        if (!isBlank(signer.keyId())) {
            header.put("kid", signer.keyId());
        }

        Map<String, Object> payload = new LinkedHashMap<String, Object>(event.toMap());
        payload.remove("event_signature");
        payload.remove("signature_key_id");

        String headerB64 = base64UrlEncode(canonicalJson(header).getBytes(StandardCharsets.UTF_8));
        String payloadB64 = base64UrlEncode(canonicalJson(payload).getBytes(StandardCharsets.UTF_8));
        String signingInput = headerB64 + "." + payloadB64;

        byte[] signature;
        try {
            signature = signer.sign(signingInput.getBytes(StandardCharsets.US_ASCII));
        } catch (Exception e) {
            throw new IllegalArgumentException("signer failed to sign event", e);
        }
        if (signature == null || signature.length == 0) {
            throw new IllegalArgumentException("signer returned an empty signature");
        }

        AIGPEvent signed = copyEvent(event);
        signed.eventSignature = signingInput + "." + base64UrlEncode(signature);
        signed.signatureKeyId = nullToEmpty(signer.keyId());
        return signed;
    }

    public static AIGPEvent createAIGPEvent(CreateEventOptions options) {
        if (options == null) {
            throw new IllegalArgumentException("options are required");
        }
        String governanceHash = nullToEmpty(options.governanceHash).trim();
        if (governanceHash.isEmpty()) {
            throw new IllegalArgumentException("governance_hash is required and cannot be empty");
        }

        AIGPEvent event = new AIGPEvent();
        event.eventId = UUID.randomUUID().toString();
        event.eventType = normalizeEventType(options.eventType);
        event.eventCategory = normalizeEventCategory(options.eventCategory);
        event.eventTime = RFC3339_MILLIS_UTC.format(Instant.now());
        event.agentId = nullToEmpty(options.agentId);
        event.governanceHash = governanceHash;
        event.traceId = isBlank(options.traceId) ? randomHex(16) : safeTrim(options.traceId);
        event.spanId = nullToEmpty(options.spanId);
        event.parentSpanId = nullToEmpty(options.parentSpanId);
        event.traceFlags = nullToEmpty(options.traceFlags);
        event.agentName = nullToEmpty(options.agentName);
        event.orgId = nullToEmpty(options.orgId);
        event.orgName = nullToEmpty(options.orgName);
        event.policyId = nullToEmpty(options.policyId);
        event.policyName = nullToEmpty(options.policyName);
        event.policyVersion = options.policyVersion;
        event.promptId = nullToEmpty(options.promptId);
        event.promptName = nullToEmpty(options.promptName);
        event.promptVersion = options.promptVersion;
        event.hashType = isBlank(options.hashType) ? "sha256" : options.hashType;
        event.dataClassification = nullToEmpty(options.dataClassification);
        event.templateRendered = options.templateRendered;
        event.denialReason = nullToEmpty(options.denialReason);
        event.violationType = nullToEmpty(options.violationType);
        event.severity = nullToEmpty(options.severity);
        event.sourceIp = nullToEmpty(options.sourceIp);
        event.requestMethod = nullToEmpty(options.requestMethod);
        event.requestPath = nullToEmpty(options.requestPath);
        event.queryHash = nullToEmpty(options.queryHash);
        event.previousHash = nullToEmpty(options.previousHash);
        event.annotations = options.annotations == null ? new LinkedHashMap<String, Object>() : options.annotations;
        event.eventSignature = nullToEmpty(options.eventSignature);
        event.signatureKeyId = nullToEmpty(options.signatureKeyId);
        event.sequenceNumber = options.sequenceNumber > 0
            ? options.sequenceNumber
            : nextSequenceNumber(event.agentId, event.traceId);
        event.causalityRef = nullToEmpty(options.causalityRef);
        event.specVersion = isBlank(options.specVersion) ? "0.10.0" : options.specVersion;
        event.governanceMerkleTree = options.governanceMerkleTree;

        return event;
    }

    public static List<String> validateAIGPEvent(AIGPEvent event) {
        List<String> errors = new ArrayList<String>();
        if (event == null) {
            errors.add("event is required");
            return errors;
        }

        if (isBlank(event.eventId)) {
            errors.add("Missing required field: event_id");
        }
        if (isBlank(event.eventType)) {
            errors.add("Missing required field: event_type");
        } else if (!EVENT_TYPE_PATTERN.matcher(event.eventType).matches()) {
            errors.add("event_type must match ^[A-Z][A-Z0-9_]*$");
        }
        if (isBlank(event.eventCategory)) {
            errors.add("Missing required field: event_category");
        }
        if (isBlank(event.eventTime)) {
            errors.add("Missing required field: event_time");
        }
        if (isBlank(event.agentId)) {
            errors.add("Missing required field: agent_id");
        }
        if (isBlank(event.traceId)) {
            errors.add("Missing required field: trace_id");
        } else if (!isValidTraceId(event.traceId, event.spanId)) {
            if (!isBlank(event.spanId)) {
                errors.add("trace_id must be 32-char lowercase hex when span_id is present");
            } else {
                errors.add("trace_id must be 32-char lowercase hex, UUID v4, or trace-/req- prefixed UUID v4");
            }
        }
        if (isBlank(event.governanceHash)) {
            errors.add("governance_hash must be a non-empty string");
        }
        if (event.sequenceNumber < 1) {
            errors.add("sequence_number must be an integer >= 1");
        }

        return errors;
    }

    private static synchronized long nextSequenceNumber(String agentId, String traceId) {
        String key = nullToEmpty(agentId).trim() + "|" + nullToEmpty(traceId).trim();
        long next = SEQUENCE_COUNTERS.containsKey(key) ? SEQUENCE_COUNTERS.get(key) + 1L : 1L;
        SEQUENCE_COUNTERS.put(key, next);
        return next;
    }

    public static String ceTypeFromEventType(String eventType) {
        return AIGP_TYPE_PREFIX + normalizeEventType(eventType).toLowerCase(Locale.ROOT);
    }

    public static String eventTypeFromCeType(String ceType) {
        if (isBlank(ceType) || !ceType.startsWith(AIGP_TYPE_PREFIX)) {
            throw new IllegalArgumentException("CloudEvents type does not start with " + AIGP_TYPE_PREFIX + ": " + ceType);
        }
        return ceType.substring(AIGP_TYPE_PREFIX.length());
    }

    public static CloudEvent wrapAsCloudEvent(AIGPEvent event, boolean includeDataschema) {
        if (event == null || isBlank(event.eventId) || isBlank(event.eventType) || isBlank(event.agentId)) {
            throw new IllegalArgumentException("AIGP event must have event_id, event_type, and agent_id to wrap as CloudEvent");
        }

        String orgId = isBlank(event.orgId) ? "default" : event.orgId;

        CloudEvent ce = new CloudEvent();
        ce.specversion = CE_SPECVERSION;
        ce.id = event.eventId;
        ce.type = ceTypeFromEventType(event.eventType);
        ce.source = AIGP_SOURCE_SCHEME + orgId + "/" + event.agentId;
        ce.datacontenttype = "application/json";
        ce.aigpagentid = event.agentId;
        ce.data = event;

        if (!isBlank(event.eventTime)) {
            ce.time = event.eventTime;
        }
        if (includeDataschema) {
            ce.dataschema = AIGP_DATA_SCHEMA;
        }
        if (!isBlank(event.policyName)) {
            ce.subject = event.policyName;
        } else if (!isBlank(event.promptName)) {
            ce.subject = event.promptName;
        }
        if (!"default".equals(orgId)) {
            ce.aigporgid = orgId;
        }
        if (!isBlank(event.eventCategory)) {
            ce.aigpcategory = event.eventCategory;
        }
        if (!isBlank(event.dataClassification)) {
            ce.aigpclassification = event.dataClassification;
        }
        if (!isBlank(event.severity)) {
            ce.aigpseverity = event.severity;
        }
        if (!isBlank(event.hashType)) {
            ce.aigphashtype = event.hashType;
        }

        return ce;
    }

    public static AIGPEvent unwrapFromCloudEvent(CloudEvent ce) {
        if (ce == null || !CE_SPECVERSION.equals(ce.specversion)) {
            throw new IllegalArgumentException("Unsupported CloudEvents specversion");
        }
        if (isBlank(ce.type) || !ce.type.startsWith(AIGP_TYPE_PREFIX)) {
            throw new IllegalArgumentException("CloudEvents type does not start with " + AIGP_TYPE_PREFIX);
        }
        if (ce.data == null) {
            throw new IllegalArgumentException("CloudEvents data must be present");
        }
        return ce.data;
    }

    public static Map<String, String> buildCEHeaders(AIGPEvent event, String prefix) {
        if (event == null) {
            throw new IllegalArgumentException("event is required");
        }

        String actualPrefix = isBlank(prefix) ? "ce-" : prefix;
        String orgId = isBlank(event.orgId) ? "default" : event.orgId;

        Map<String, String> headers = new LinkedHashMap<String, String>();
        headers.put(actualPrefix + "specversion", CE_SPECVERSION);
        headers.put(actualPrefix + "id", nullToEmpty(event.eventId));
        headers.put(actualPrefix + "type", ceTypeFromEventType(event.eventType));
        headers.put(actualPrefix + "source", AIGP_SOURCE_SCHEME + orgId + "/" + nullToEmpty(event.agentId));
        headers.put(actualPrefix + "aigpagentid", nullToEmpty(event.agentId));

        if (!isBlank(event.eventTime)) {
            headers.put(actualPrefix + "time", event.eventTime);
        }
        if (!"default".equals(orgId)) {
            headers.put(actualPrefix + "aigporgid", orgId);
        }
        if (!isBlank(event.eventCategory)) {
            headers.put(actualPrefix + "aigpcategory", event.eventCategory);
        }
        if (!isBlank(event.dataClassification)) {
            headers.put(actualPrefix + "aigpclassification", event.dataClassification);
        }
        if (!isBlank(event.severity)) {
            headers.put(actualPrefix + "aigpseverity", event.severity);
        }
        if (!isBlank(event.hashType)) {
            headers.put(actualPrefix + "aigphashtype", event.hashType);
        }

        return headers;
    }

    private static AIGPEvent copyEvent(AIGPEvent src) {
        if (src == null) {
            return null;
        }

        AIGPEvent out = new AIGPEvent();
        out.eventId = src.eventId;
        out.eventType = src.eventType;
        out.eventCategory = src.eventCategory;
        out.eventTime = src.eventTime;
        out.agentId = src.agentId;
        out.governanceHash = src.governanceHash;
        out.traceId = src.traceId;
        out.spanId = src.spanId;
        out.parentSpanId = src.parentSpanId;
        out.traceFlags = src.traceFlags;
        out.agentName = src.agentName;
        out.orgId = src.orgId;
        out.orgName = src.orgName;
        out.policyId = src.policyId;
        out.policyName = src.policyName;
        out.policyVersion = src.policyVersion;
        out.promptId = src.promptId;
        out.promptName = src.promptName;
        out.promptVersion = src.promptVersion;
        out.hashType = src.hashType;
        out.dataClassification = src.dataClassification;
        out.templateRendered = src.templateRendered;
        out.denialReason = src.denialReason;
        out.violationType = src.violationType;
        out.severity = src.severity;
        out.sourceIp = src.sourceIp;
        out.requestMethod = src.requestMethod;
        out.requestPath = src.requestPath;
        out.queryHash = src.queryHash;
        out.previousHash = src.previousHash;
        out.annotations = src.annotations == null ? new LinkedHashMap<String, Object>() : new LinkedHashMap<String, Object>(src.annotations);
        out.eventSignature = src.eventSignature;
        out.signatureKeyId = src.signatureKeyId;
        out.sequenceNumber = src.sequenceNumber;
        out.causalityRef = src.causalityRef;
        out.specVersion = src.specVersion;
        out.governanceMerkleTree = src.governanceMerkleTree;
        return out;
    }

    private static void sleepQuietly(long delayMs) {
        if (delayMs <= 0L) {
            return;
        }
        try {
            Thread.sleep(delayMs);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
    }

    private static String base64UrlEncode(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String canonicalJson(Object value) {
        if (value == null) {
            return "null";
        }
        if (value instanceof String) {
            return quoteJson((String) value);
        }
        if (value instanceof Number || value instanceof Boolean) {
            return String.valueOf(value);
        }
        if (value instanceof Map<?, ?>) {
            List<String> keys = new ArrayList<String>();
            for (Object key : ((Map<?, ?>) value).keySet()) {
                keys.add(String.valueOf(key));
            }
            Collections.sort(keys);
            List<String> pairs = new ArrayList<String>(keys.size());
            for (String key : keys) {
                Object item = ((Map<?, ?>) value).get(key);
                pairs.add(quoteJson(key) + ":" + canonicalJson(item));
            }
            return "{" + String.join(",", pairs) + "}";
        }
        if (value instanceof Iterable<?>) {
            List<String> parts = new ArrayList<String>();
            for (Object item : (Iterable<?>) value) {
                parts.add(canonicalJson(item));
            }
            return "[" + String.join(",", parts) + "]";
        }
        if (value.getClass().isArray()) {
            int length = java.lang.reflect.Array.getLength(value);
            List<String> parts = new ArrayList<String>(length);
            for (int i = 0; i < length; i++) {
                parts.add(canonicalJson(java.lang.reflect.Array.get(value, i)));
            }
            return "[" + String.join(",", parts) + "]";
        }
        return quoteJson(String.valueOf(value));
    }

    private static String quoteJson(String value) {
        StringBuilder out = new StringBuilder(value.length() + 2);
        out.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"':
                    out.append("\\\"");
                    break;
                case '\\':
                    out.append("\\\\");
                    break;
                case '\b':
                    out.append("\\b");
                    break;
                case '\f':
                    out.append("\\f");
                    break;
                case '\n':
                    out.append("\\n");
                    break;
                case '\r':
                    out.append("\\r");
                    break;
                case '\t':
                    out.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        out.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
            }
        }
        out.append('"');
        return out.toString();
    }

    private static String computeMerkleRoot(List<String> sortedHashes) {
        if (sortedHashes == null || sortedHashes.isEmpty()) {
            throw new IllegalArgumentException("Cannot compute Merkle root of empty list");
        }
        if (sortedHashes.size() == 1) {
            return sortedHashes.get(0);
        }

        List<String> level = new ArrayList<String>(sortedHashes);
        while (level.size() > 1) {
            List<String> next = new ArrayList<String>();
            for (int i = 0; i < level.size(); i += 2) {
                if (i + 1 >= level.size()) {
                    next.add(level.get(i));
                } else {
                    next.add(computeGovernanceHash(level.get(i) + level.get(i + 1), "sha256"));
                }
            }
            level = next;
        }

        return level.get(0);
    }

    private static String digestHex(String algorithm, String content) {
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            byte[] bytes = digest.digest(content.getBytes(StandardCharsets.UTF_8));
            return toHex(bytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Digest algorithm unavailable: " + algorithm, e);
        }
    }

    private static String randomHex(int bytes) {
        byte[] random = new byte[bytes];
        SECURE_RANDOM.nextBytes(random);
        return toHex(random);
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format(Locale.ROOT, "%02x", b & 0xff));
        }
        return sb.toString();
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }

    private static String safeTrim(String value) {
        return value == null ? "" : value.trim();
    }

    private static boolean isValidTraceId(String traceId, String spanId) {
        if (!isBlank(spanId)) {
            return TRACE_ID_OTEL_PATTERN.matcher(traceId).matches();
        }
        return TRACE_ID_OTEL_PATTERN.matcher(traceId).matches()
            || TRACE_ID_UUID_V4_PATTERN.matcher(traceId).matches()
            || TRACE_ID_PREFIXED_UUID_V4_PATTERN.matcher(traceId).matches();
    }

    private static boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }
}
