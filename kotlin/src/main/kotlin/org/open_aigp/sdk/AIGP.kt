package org.open_aigp.sdk

import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Base64
import java.util.UUID

const val VERSION: String = "0.1.0"
const val CE_SPECVERSION: String = "1.0"
const val AIGP_TYPE_PREFIX: String = "org.aigp.v1."
const val AIGP_SOURCE_SCHEME: String = "aigp://"
const val AIGP_DATA_SCHEMA: String = "https://open-aigp.org/schema/aigp-event.schema.json"

private val resourceTypePattern = Regex("^[a-z][a-z0-9]*(-[a-z0-9]+)*$")
private val eventTypePattern = Regex("^[A-Z][A-Z0-9_]*$")
private val traceIdOtelPattern = Regex("^[a-f0-9]{32}$")
private val traceIdUuidV4Pattern = Regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
private val traceIdPrefixedUuidV4Pattern = Regex("^(trace|req)-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
private val rfc3339MillisUtcFormatter: DateTimeFormatter =
    DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC)
private val sequenceCounters = mutableMapOf<String, Long>()

private val eventTypeAliases = mapOf(
    "governance.policy.delivered" to "INJECT_SUCCESS",
    "governance.policy.denied" to "INJECT_DENIED",
    "governance.prompt.delivered" to "PROMPT_USED",
    "governance.prompt.denied" to "PROMPT_DENIED",
    "governance.policy.violation" to "POLICY_VIOLATION",
    "governance.a2a.call" to "A2A_CALL",
    "governance.tool.invoked" to "TOOL_INVOKED",
    "governance.tool.denied" to "TOOL_DENIED",
    "governance.boundary.unverified" to "UNVERIFIED_BOUNDARY",
    "governance.inference.started" to "INFERENCE_STARTED",
    "governance.inference.completed" to "INFERENCE_COMPLETED",
    "governance.inference.blocked" to "INFERENCE_BLOCKED",
    "governance.model.loaded" to "MODEL_LOADED",
    "governance.model.switched" to "MODEL_SWITCHED",
    "governance.memory.read" to "MEMORY_READ",
    "governance.memory.written" to "MEMORY_WRITTEN",
    "governance.proof" to "GOVERNANCE_PROOF",
    "governance.proof.delivered" to "GOVERNANCE_PROOF",
)

private val random = SecureRandom()

interface EventSigner {
    val algorithm: String
    val keyId: String
    fun sign(signingInput: ByteArray): ByteArray
}

data class RetryPolicy(
    val maxAttempts: Int = 3,
    val baseDelayMs: Long = 100,
    val maxDelayMs: Long = 2000,
) {
    fun delayForAttempt(attempt: Int): Long {
        val exponent = (attempt.coerceAtLeast(1) - 1).coerceAtMost(30)
        val delay = baseDelayMs * (1L shl exponent)
        return minOf(delay, maxDelayMs)
    }
}

data class FlushResult(
    val delivered: Int,
    val pending: Int,
)

class ReliableEmitter(
    private val sender: (AIGPEvent) -> Unit,
    private val retryPolicy: RetryPolicy = RetryPolicy(),
    private val idempotent: Boolean = true,
    private val sleepFn: (Long) -> Unit = { Thread.sleep(it) },
) {
    private val deliveredIds = mutableSetOf<String>()
    private val failedEvents = mutableListOf<AIGPEvent>()

    val pendingCount: Int
        get() = synchronized(failedEvents) { failedEvents.size }

    fun emit(event: AIGPEvent): Boolean {
        val eventId = event.eventId.trim()
        synchronized(failedEvents) {
            if (idempotent && eventId.isNotEmpty() && deliveredIds.contains(eventId)) {
                return true
            }
        }

        val attempts = retryPolicy.maxAttempts.coerceAtLeast(1)
        repeat(attempts) { idx ->
            val attempt = idx + 1
            try {
                sender(event)
                synchronized(failedEvents) {
                    if (eventId.isNotEmpty()) {
                        deliveredIds.add(eventId)
                    }
                }
                return true
            } catch (_: Exception) {
                if (attempt < attempts) {
                    sleepFn(retryPolicy.delayForAttempt(attempt))
                }
            }
        }

        synchronized(failedEvents) {
            failedEvents.add(event.copy(annotations = event.annotations.toMap()))
        }
        return false
    }

    fun flushFailed(maxItems: Int = 1000): FlushResult {
        val limit = if (maxItems > 0) maxItems else 1000
        val snapshot = synchronized(failedEvents) {
            failedEvents.toList()
        }
        val remaining = mutableListOf<AIGPEvent>()
        var delivered = 0

        for ((index, event) in snapshot.withIndex()) {
            if (index >= limit) {
                remaining.add(event)
                continue
            }
            if (emit(event)) {
                delivered += 1
            } else {
                remaining.add(event)
            }
        }

        synchronized(failedEvents) {
            failedEvents.clear()
            failedEvents.addAll(remaining)
            return FlushResult(delivered = delivered, pending = failedEvents.size)
        }
    }
}

data class MerkleLeaf(
    val resourceType: String,
    val resourceName: String,
    val hash: String,
    val hashMode: String? = null,
    val contentRef: String? = null,
)

data class MerkleProofStep(
    val siblingHash: String,
    val siblingPosition: String,
)

data class MerkleInclusionProof(
    val leafHash: String,
    val proofPath: List<MerkleProofStep>,
)

data class GovernanceMerkleTree(
    val algorithm: String,
    val leafCount: Int,
    val leaves: List<MerkleLeaf>,
    val inclusionProofs: List<MerkleInclusionProof>? = null,
)

data class MerkleResult(
    val rootHash: String,
    val merkleTree: GovernanceMerkleTree?,
)

data class Resource(
    val resourceType: String,
    val resourceName: String,
    val content: String,
    val hashMode: String = "content",
    val contentRef: String = "",
)

data class CreateEventOptions(
    val eventType: String,
    val eventCategory: String = "",
    val agentId: String,
    val traceId: String = "",
    val governanceHash: String = "",
    val spanId: String = "",
    val parentSpanId: String = "",
    val traceFlags: String = "",
    val agentName: String = "",
    val orgId: String = "",
    val orgName: String = "",
    val policyId: String = "",
    val policyName: String = "",
    val policyVersion: Int = 0,
    val promptId: String = "",
    val promptName: String = "",
    val promptVersion: Int = 0,
    val hashType: String = "sha256",
    val dataClassification: String = "",
    val templateRendered: Boolean = false,
    val denialReason: String = "",
    val violationType: String = "",
    val severity: String = "",
    val sourceIp: String = "",
    val requestMethod: String = "",
    val requestPath: String = "",
    val queryHash: String = "",
    val previousHash: String = "",
    val annotations: Map<String, Any> = emptyMap(),
    val eventSignature: String = "",
    val signatureKeyId: String = "",
    val sequenceNumber: Long = 0,
    val causalityRef: String = "",
    val specVersion: String = "0.10.0",
    val governanceMerkleTree: GovernanceMerkleTree? = null,
)

data class AIGPEvent(
    val eventId: String,
    val eventType: String,
    val eventCategory: String,
    val eventTime: String,
    val agentId: String,
    val governanceHash: String,
    val traceId: String,
    val spanId: String,
    val parentSpanId: String,
    val traceFlags: String,
    val agentName: String,
    val orgId: String,
    val orgName: String,
    val policyId: String,
    val policyName: String,
    val policyVersion: Int,
    val promptId: String,
    val promptName: String,
    val promptVersion: Int,
    val hashType: String,
    val dataClassification: String,
    val templateRendered: Boolean,
    val denialReason: String,
    val violationType: String,
    val severity: String,
    val sourceIp: String,
    val requestMethod: String,
    val requestPath: String,
    val queryHash: String,
    val previousHash: String,
    val annotations: Map<String, Any>,
    val eventSignature: String,
    val signatureKeyId: String,
    val sequenceNumber: Long,
    val causalityRef: String,
    val specVersion: String,
    val governanceMerkleTree: GovernanceMerkleTree? = null,
)

data class CloudEvent(
    val specversion: String,
    val id: String,
    val type: String,
    val source: String,
    val datacontenttype: String,
    val data: AIGPEvent,
    val time: String? = null,
    val dataschema: String? = null,
    val subject: String? = null,
    val aigpagentid: String,
    val aigporgid: String? = null,
    val aigpcategory: String? = null,
    val aigpclassification: String? = null,
    val aigpseverity: String? = null,
    val aigphashtype: String? = null,
)

fun normalizeEventType(eventType: String): String {
    val raw = eventType.trim()
    require(raw.isNotEmpty()) { "event_type must be a non-empty string" }

    val mapped = eventTypeAliases[raw] ?: raw
    if (eventTypePattern.matches(mapped)) {
        return mapped
    }

    val normalized = mapped
        .replace(Regex("[^A-Za-z0-9]+"), "_")
        .trim('_')
        .uppercase()

    require(normalized.isNotEmpty() && eventTypePattern.matches(normalized)) {
        "event_type cannot be normalized to valid UPPER_SNAKE_CASE: $eventType"
    }

    return normalized
}

fun normalizeEventCategory(eventCategory: String): String {
    val raw = eventCategory.trim().lowercase()
    if (raw.isEmpty()) {
        return "governance"
    }

    val normalized = raw
        .replace('_', '-')
        .replace(Regex("[^a-z0-9-]+"), "-")
        .trim('-')

    return if (normalized.isEmpty()) "governance" else normalized
}

fun computeGovernanceHash(content: String, algorithm: String = "sha256"): String {
    val digestAlgorithm = when (algorithm) {
        "sha256" -> "SHA-256"
        "sha384" -> "SHA-384"
        "sha512" -> "SHA-512"
        else -> throw IllegalArgumentException("Unsupported hash algorithm: $algorithm")
    }

    val digest = MessageDigest.getInstance(digestAlgorithm)
    return digest.digest(content.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it.toInt() and 0xff) }
}

fun computeLeafHash(
    resourceType: String,
    resourceName: String,
    content: String,
    hashMode: String = "content",
    contentRef: String = "",
): String {
    require(resourceTypePattern.matches(resourceType)) {
        "Invalid resource_type: $resourceType"
    }
    require(hashMode == "content" || hashMode == "pointer") {
        "Unsupported hash_mode: $hashMode (expected 'content' or 'pointer')"
    }

    val hashable = if (hashMode == "pointer") {
        require(contentRef.isNotBlank()) { "content_ref is required when hash_mode='pointer'" }
        contentRef
    } else {
        content
    }

    return computeGovernanceHash("$resourceType:$resourceName:$hashable", "sha256")
}

fun computeMerkleGovernanceHash(resources: List<Resource>): MerkleResult {
    return computeMerkleGovernanceHash(resources, includeInclusionProofs = false)
}

fun computeMerkleGovernanceHash(
    resources: List<Resource>,
    includeInclusionProofs: Boolean = false,
): MerkleResult {
    require(resources.isNotEmpty()) { "At least one resource is required" }

    if (resources.size == 1) {
        val single = resources[0]
        require(single.hashMode == "content" || single.hashMode == "pointer") {
            "Unsupported hash_mode: ${single.hashMode} (expected 'content' or 'pointer')"
        }
        if (single.hashMode == "pointer") {
            require(single.contentRef.isNotBlank()) { "content_ref is required when hash_mode='pointer'" }
            return MerkleResult(computeGovernanceHash(single.contentRef, "sha256"), null)
        }
        return MerkleResult(computeGovernanceHash(single.content, "sha256"), null)
    }

    val leaves = resources.map { resource ->
        val hash = computeLeafHash(
            resourceType = resource.resourceType,
            resourceName = resource.resourceName,
            content = resource.content,
            hashMode = resource.hashMode,
            contentRef = resource.contentRef,
        )

        MerkleLeaf(
            resourceType = resource.resourceType,
            resourceName = resource.resourceName,
            hash = hash,
            hashMode = resource.hashMode.takeUnless { it == "content" },
            contentRef = resource.contentRef.takeIf { it.isNotBlank() },
        )
    }.sortedBy { it.hash }

    val root = computeMerkleRoot(leaves.map { it.hash })

    val inclusionProofs = if (includeInclusionProofs) {
        buildInclusionProofs(leaves)
    } else {
        null
    }

    return MerkleResult(
        rootHash = root,
        merkleTree = GovernanceMerkleTree(
            algorithm = "sha256",
            leafCount = leaves.size,
            leaves = leaves,
            inclusionProofs = inclusionProofs,
        ),
    )
}

fun buildInclusionProofs(leaves: List<MerkleLeaf>): List<MerkleInclusionProof> {
    if (leaves.isEmpty()) {
        return emptyList()
    }

    data class Node(val hash: String, val leafIndexes: List<Int>)

    val proofPaths = MutableList(leaves.size) { mutableListOf<MerkleProofStep>() }
    var nodes = leaves.mapIndexed { index, leaf ->
        Node(hash = leaf.hash, leafIndexes = listOf(index))
    }

    while (nodes.size > 1) {
        val next = mutableListOf<Node>()
        var i = 0
        while (i < nodes.size) {
            if (i + 1 >= nodes.size) {
                next.add(nodes[i])
                i += 1
                continue
            }

            val left = nodes[i]
            val right = nodes[i + 1]
            left.leafIndexes.forEach { leafIndex ->
                proofPaths[leafIndex].add(MerkleProofStep(siblingHash = right.hash, siblingPosition = "right"))
            }
            right.leafIndexes.forEach { leafIndex ->
                proofPaths[leafIndex].add(MerkleProofStep(siblingHash = left.hash, siblingPosition = "left"))
            }

            next.add(
                Node(
                    hash = computeGovernanceHash(left.hash + right.hash, "sha256"),
                    leafIndexes = left.leafIndexes + right.leafIndexes,
                )
            )
            i += 2
        }
        nodes = next
    }

    return leaves.mapIndexed { index, leaf ->
        MerkleInclusionProof(leafHash = leaf.hash, proofPath = proofPaths[index].toList())
    }
}

fun verifyInclusionProof(
    rootHash: String,
    leafHash: String,
    proofPath: List<MerkleProofStep>,
): Boolean {
    var current = leafHash.trim()
    val expected = rootHash.trim()
    if (current.isEmpty() || expected.isEmpty()) {
        return false
    }

    for (step in proofPath) {
        if (step.siblingHash.isBlank()) {
            return false
        }
        current = when (step.siblingPosition) {
            "left" -> computeGovernanceHash(step.siblingHash + current, "sha256")
            "right" -> computeGovernanceHash(current + step.siblingHash, "sha256")
            else -> throw IllegalArgumentException(
                "Invalid sibling_position in proof step: ${step.siblingPosition} (expected 'left' or 'right')"
            )
        }
    }

    return current == expected
}

fun signEventWithSigner(event: AIGPEvent, signer: EventSigner): AIGPEvent {
    val header = linkedMapOf<String, Any>(
        "alg" to if (signer.algorithm.isBlank()) "ES256" else signer.algorithm,
        "typ" to "JWT",
    )
    if (signer.keyId.isNotBlank()) {
        header["kid"] = signer.keyId
    }

    val payload = event.toSignableMap()
    val headerB64 = base64UrlEncode(canonicalJson(header).toByteArray(Charsets.UTF_8))
    val payloadB64 = base64UrlEncode(canonicalJson(payload).toByteArray(Charsets.UTF_8))
    val signingInput = "$headerB64.$payloadB64"
    val signature = signer.sign(signingInput.toByteArray(Charsets.US_ASCII))
    require(signature.isNotEmpty()) { "signer returned an empty signature" }

    return event.copy(
        eventSignature = "$signingInput.${base64UrlEncode(signature)}",
        signatureKeyId = signer.keyId,
    )
}

fun createAIGPEvent(options: CreateEventOptions): AIGPEvent {
    val governanceHash = options.governanceHash.trim()
    require(governanceHash.isNotEmpty()) { "governance_hash is required and cannot be empty" }
    val traceId = options.traceId.trim().ifBlank { randomHex(16) }
    val sequenceNumber = if (options.sequenceNumber > 0) {
        options.sequenceNumber
    } else {
        nextSequenceNumber(options.agentId, traceId)
    }

    return AIGPEvent(
        eventId = UUID.randomUUID().toString(),
        eventType = normalizeEventType(options.eventType),
        eventCategory = normalizeEventCategory(options.eventCategory),
        eventTime = rfc3339MillisUtcFormatter.format(Instant.now()),
        agentId = options.agentId,
        governanceHash = governanceHash,
        traceId = traceId,
        spanId = options.spanId,
        parentSpanId = options.parentSpanId,
        traceFlags = options.traceFlags,
        agentName = options.agentName,
        orgId = options.orgId,
        orgName = options.orgName,
        policyId = options.policyId,
        policyName = options.policyName,
        policyVersion = options.policyVersion,
        promptId = options.promptId,
        promptName = options.promptName,
        promptVersion = options.promptVersion,
        hashType = options.hashType,
        dataClassification = options.dataClassification,
        templateRendered = options.templateRendered,
        denialReason = options.denialReason,
        violationType = options.violationType,
        severity = options.severity,
        sourceIp = options.sourceIp,
        requestMethod = options.requestMethod,
        requestPath = options.requestPath,
        queryHash = options.queryHash,
        previousHash = options.previousHash,
        annotations = options.annotations,
        eventSignature = options.eventSignature,
        signatureKeyId = options.signatureKeyId,
        sequenceNumber = sequenceNumber,
        causalityRef = options.causalityRef,
        specVersion = options.specVersion,
        governanceMerkleTree = options.governanceMerkleTree,
    )
}

fun validateAIGPEvent(event: AIGPEvent): List<String> {
    val errors = mutableListOf<String>()

    if (event.eventId.isBlank()) errors.add("Missing required field: event_id")
    if (event.eventType.isBlank()) {
        errors.add("Missing required field: event_type")
    } else if (!eventTypePattern.matches(event.eventType)) {
        errors.add("event_type must match ^[A-Z][A-Z0-9_]*$")
    }
    if (event.eventCategory.isBlank()) errors.add("Missing required field: event_category")
    if (event.eventTime.isBlank()) errors.add("Missing required field: event_time")
    if (event.agentId.isBlank()) errors.add("Missing required field: agent_id")
    if (event.traceId.isBlank()) {
        errors.add("Missing required field: trace_id")
    } else if (!isValidTraceId(event.traceId, event.spanId)) {
        if (event.spanId.isNotBlank()) {
            errors.add("trace_id must be 32-char lowercase hex when span_id is present")
        } else {
            errors.add("trace_id must be 32-char lowercase hex, UUID v4, or trace-/req- prefixed UUID v4")
        }
    }
    if (event.governanceHash.isBlank()) {
        errors.add("governance_hash must be a non-empty string")
    }
    if (event.sequenceNumber < 1) {
        errors.add("sequence_number must be an integer >= 1")
    }

    return errors
}

private fun nextSequenceNumber(agentId: String, traceId: String): Long {
    val key = "${agentId.trim()}|${traceId.trim()}"
    synchronized(sequenceCounters) {
        val next = (sequenceCounters[key] ?: 0L) + 1L
        sequenceCounters[key] = next
        return next
    }
}

fun ceTypeFromEventType(eventType: String): String {
    return "$AIGP_TYPE_PREFIX${normalizeEventType(eventType).lowercase()}"
}

private fun isValidTraceId(traceId: String, spanId: String): Boolean {
    if (spanId.isNotBlank()) {
        return traceIdOtelPattern.matches(traceId)
    }
    return traceIdOtelPattern.matches(traceId) ||
        traceIdUuidV4Pattern.matches(traceId) ||
        traceIdPrefixedUuidV4Pattern.matches(traceId)
}

fun eventTypeFromCeType(ceType: String): String {
    require(ceType.startsWith(AIGP_TYPE_PREFIX)) {
        "CloudEvents type does not start with $AIGP_TYPE_PREFIX: $ceType"
    }
    return ceType.removePrefix(AIGP_TYPE_PREFIX)
}

fun wrapAsCloudEvent(event: AIGPEvent, includeDataschema: Boolean = true): CloudEvent {
    require(event.eventId.isNotBlank() && event.eventType.isNotBlank() && event.agentId.isNotBlank()) {
        "AIGP event must have event_id, event_type, and agent_id to wrap as CloudEvent"
    }

    val orgId = event.orgId.ifBlank { "default" }

    return CloudEvent(
        specversion = CE_SPECVERSION,
        id = event.eventId,
        type = ceTypeFromEventType(event.eventType),
        source = "$AIGP_SOURCE_SCHEME$orgId/${event.agentId}",
        datacontenttype = "application/json",
        data = event,
        time = event.eventTime.takeIf { it.isNotBlank() },
        dataschema = AIGP_DATA_SCHEMA.takeIf { includeDataschema },
        subject = event.policyName.ifBlank { event.promptName }.takeIf { it.isNotBlank() },
        aigpagentid = event.agentId,
        aigporgid = orgId.takeUnless { it == "default" },
        aigpcategory = event.eventCategory.takeIf { it.isNotBlank() },
        aigpclassification = event.dataClassification.takeIf { it.isNotBlank() },
        aigpseverity = event.severity.takeIf { it.isNotBlank() },
        aigphashtype = event.hashType.takeIf { it.isNotBlank() },
    )
}

fun unwrapFromCloudEvent(ce: CloudEvent): AIGPEvent {
    require(ce.specversion == CE_SPECVERSION) {
        "Unsupported CloudEvents specversion: ${ce.specversion}"
    }
    require(ce.type.startsWith(AIGP_TYPE_PREFIX)) {
        "CloudEvents type does not start with $AIGP_TYPE_PREFIX"
    }
    return ce.data
}

fun buildCEHeaders(event: AIGPEvent, prefix: String = "ce-"): Map<String, String> {
    val orgId = event.orgId.ifBlank { "default" }

    return buildMap {
        put("${prefix}specversion", CE_SPECVERSION)
        put("${prefix}id", event.eventId)
        put("${prefix}type", ceTypeFromEventType(event.eventType))
        put("${prefix}source", "$AIGP_SOURCE_SCHEME$orgId/${event.agentId}")
        put("${prefix}aigpagentid", event.agentId)
        event.eventTime.takeIf { it.isNotBlank() }?.let { put("${prefix}time", it) }
        orgId.takeUnless { it == "default" }?.let { put("${prefix}aigporgid", it) }
        event.eventCategory.takeIf { it.isNotBlank() }?.let { put("${prefix}aigpcategory", it) }
        event.dataClassification.takeIf { it.isNotBlank() }?.let { put("${prefix}aigpclassification", it) }
        event.severity.takeIf { it.isNotBlank() }?.let { put("${prefix}aigpseverity", it) }
        event.hashType.takeIf { it.isNotBlank() }?.let { put("${prefix}aigphashtype", it) }
    }
}

private fun AIGPEvent.toSignableMap(): Map<String, Any> {
    val out = linkedMapOf<String, Any>(
        "event_id" to eventId,
        "event_type" to eventType,
        "event_category" to eventCategory,
        "event_time" to eventTime,
        "agent_id" to agentId,
        "governance_hash" to governanceHash,
        "trace_id" to traceId,
        "span_id" to spanId,
        "parent_span_id" to parentSpanId,
        "trace_flags" to traceFlags,
        "agent_name" to agentName,
        "org_id" to orgId,
        "org_name" to orgName,
        "policy_id" to policyId,
        "policy_name" to policyName,
        "policy_version" to policyVersion,
        "prompt_id" to promptId,
        "prompt_name" to promptName,
        "prompt_version" to promptVersion,
        "hash_type" to hashType,
        "data_classification" to dataClassification,
        "template_rendered" to templateRendered,
        "denial_reason" to denialReason,
        "violation_type" to violationType,
        "severity" to severity,
        "source_ip" to sourceIp,
        "request_method" to requestMethod,
        "request_path" to requestPath,
        "query_hash" to queryHash,
        "previous_hash" to previousHash,
        "annotations" to annotations,
        "sequence_number" to sequenceNumber,
        "causality_ref" to causalityRef,
        "spec_version" to specVersion,
    )
    governanceMerkleTree?.let { tree ->
        out["governance_merkle_tree"] = linkedMapOf(
            "algorithm" to tree.algorithm,
            "leaf_count" to tree.leafCount,
            "leaves" to tree.leaves.map { leaf ->
                linkedMapOf<String, Any?>(
                    "resource_type" to leaf.resourceType,
                    "resource_name" to leaf.resourceName,
                    "hash" to leaf.hash,
                    "hash_mode" to leaf.hashMode,
                    "content_ref" to leaf.contentRef,
                ).filterValues { it != null }
            },
            "inclusion_proofs" to tree.inclusionProofs?.map { proof ->
                linkedMapOf<String, Any>(
                    "leaf_hash" to proof.leafHash,
                    "proof_path" to proof.proofPath.map { step ->
                        linkedMapOf(
                            "sibling_hash" to step.siblingHash,
                            "sibling_position" to step.siblingPosition,
                        )
                    },
                )
            },
        ).filterValues { it != null }
    }
    return out
}

private fun canonicalJson(value: Any?): String {
    return when (value) {
        null -> "null"
        is String -> quoteJson(value)
        is Boolean, is Number -> value.toString()
        is Map<*, *> -> {
            value.entries
                .map { it.key.toString() to it.value }
                .sortedBy { it.first }
                .joinToString(prefix = "{", postfix = "}") { (key, item) ->
                    "${quoteJson(key)}:${canonicalJson(item)}"
            }
        }
        is Iterable<*> -> value.joinToString(prefix = "[", postfix = "]") { canonicalJson(it) }
        is Array<*> -> value.joinToString(prefix = "[", postfix = "]") { canonicalJson(it) }
        else -> quoteJson(value.toString())
    }
}

private fun quoteJson(value: String): String {
    val out = StringBuilder(value.length + 2)
    out.append('"')
    value.forEach { ch ->
        when (ch) {
            '"' -> out.append("\\\"")
            '\\' -> out.append("\\\\")
            '\b' -> out.append("\\b")
            '\u000c' -> out.append("\\f")
            '\n' -> out.append("\\n")
            '\r' -> out.append("\\r")
            '\t' -> out.append("\\t")
            else -> if (ch.code < 0x20) {
                out.append("\\u%04x".format(ch.code))
            } else {
                out.append(ch)
            }
        }
    }
    out.append('"')
    return out.toString()
}

private fun base64UrlEncode(bytes: ByteArray): String {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
}

private fun computeMerkleRoot(sortedHashes: List<String>): String {
    require(sortedHashes.isNotEmpty()) { "Cannot compute Merkle root of empty list" }
    if (sortedHashes.size == 1) {
        return sortedHashes.first()
    }

    var level = sortedHashes
    while (level.size > 1) {
        val next = mutableListOf<String>()
        var i = 0
        while (i < level.size) {
            if (i + 1 >= level.size) {
                next.add(level[i])
            } else {
                next.add(computeGovernanceHash(level[i] + level[i + 1], "sha256"))
            }
            i += 2
        }
        level = next
    }

    return level.first()
}

private fun randomHex(bytes: Int): String {
    val out = ByteArray(bytes)
    random.nextBytes(out)
    return out.joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
