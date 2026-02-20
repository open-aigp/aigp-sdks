"use strict";

const crypto = require("crypto");

const VERSION = "0.1.0";

const CE_SPECVERSION = "1.0";
const AIGP_TYPE_PREFIX = "org.aigp.v1.";
const AIGP_SOURCE_SCHEME = "aigp://";
const AIGP_DATA_SCHEMA = "https://open-aigp.org/schema/aigp-event.schema.json";

const RESOURCE_TYPE_PATTERN = /^[a-z][a-z0-9]*(-[a-z0-9]+)*$/;
const EVENT_TYPE_PATTERN = /^[A-Z][A-Z0-9_]*$/;
const TRACE_ID_OTEL_PATTERN = /^[a-f0-9]{32}$/;
const TRACE_ID_UUID_V4_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const TRACE_ID_PREFIXED_UUID_V4_PATTERN = /^(trace|req)-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const sequenceCounters = new Map();

const EVENT_TYPE_ALIASES = {
  "governance.policy.delivered": "INJECT_SUCCESS",
  "governance.policy.denied": "INJECT_DENIED",
  "governance.prompt.delivered": "PROMPT_USED",
  "governance.prompt.denied": "PROMPT_DENIED",
  "governance.policy.violation": "POLICY_VIOLATION",
  "governance.a2a.call": "A2A_CALL",
  "governance.tool.invoked": "TOOL_INVOKED",
  "governance.tool.denied": "TOOL_DENIED",
  "governance.boundary.unverified": "UNVERIFIED_BOUNDARY",
  "governance.inference.started": "INFERENCE_STARTED",
  "governance.inference.completed": "INFERENCE_COMPLETED",
  "governance.inference.blocked": "INFERENCE_BLOCKED",
  "governance.model.loaded": "MODEL_LOADED",
  "governance.model.switched": "MODEL_SWITCHED",
  "governance.memory.read": "MEMORY_READ",
  "governance.memory.written": "MEMORY_WRITTEN",
  "governance.proof": "GOVERNANCE_PROOF",
  "governance.proof.delivered": "GOVERNANCE_PROOF",
};

function randomHex(bytes) {
  return crypto.randomBytes(bytes).toString("hex");
}

function generateEventId() {
  if (typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  const buf = crypto.randomBytes(16);
  buf[6] = (buf[6] & 0x0f) | 0x40;
  buf[8] = (buf[8] & 0x3f) | 0x80;
  const hex = buf.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function normalizeEventType(eventType) {
  const raw = String(eventType || "").trim();
  if (!raw) {
    throw new Error("event_type must be a non-empty string");
  }

  const mapped = EVENT_TYPE_ALIASES[raw] || raw;
  if (EVENT_TYPE_PATTERN.test(mapped)) {
    return mapped;
  }

  const normalized = mapped.replace(/[^A-Za-z0-9]+/g, "_").replace(/^_+|_+$/g, "").toUpperCase();
  if (!normalized || !EVENT_TYPE_PATTERN.test(normalized)) {
    throw new Error(`event_type ${JSON.stringify(eventType)} cannot be normalized to a valid UPPER_SNAKE_CASE value`);
  }
  return normalized;
}

function normalizeEventCategory(eventCategory) {
  const raw = String(eventCategory || "").trim().toLowerCase();
  if (!raw) {
    return "governance";
  }
  const normalized = raw.replace(/_/g, "-").replace(/[^a-z0-9-]+/g, "-").replace(/^-+|-+$/g, "");
  return normalized || "governance";
}

function nextSequenceNumber(agentId, traceId) {
  const key = `${agentId || ""}|${traceId || ""}`;
  const next = (sequenceCounters.get(key) || 0) + 1;
  sequenceCounters.set(key, next);
  return next;
}

function hasOwn(obj, key) {
  return Object.prototype.hasOwnProperty.call(obj, key);
}

function computeGovernanceHash(content, algorithm = "sha256") {
  const supported = new Set(["sha256", "sha384", "sha512"]);
  if (!supported.has(algorithm)) {
    throw new Error(`Unsupported hash algorithm: ${algorithm}`);
  }
  return crypto.createHash(algorithm).update(String(content), "utf8").digest("hex");
}

function computeLeafHash(resourceType, resourceName, content, options = {}) {
  if (!RESOURCE_TYPE_PATTERN.test(String(resourceType))) {
    throw new Error(
      `Invalid resource_type ${JSON.stringify(resourceType)}. Must match ^[a-z][a-z0-9]*(-[a-z0-9]+)*$`
    );
  }

  const hashMode = options.hash_mode || options.hashMode || "content";
  const contentRef = options.content_ref || options.contentRef || "";
  if (hashMode !== "content" && hashMode !== "pointer") {
    throw new Error(`Unsupported hash_mode: ${JSON.stringify(hashMode)} (expected "content" or "pointer")`);
  }
  const hashable = hashMode === "pointer" ? contentRef : String(content || "");
  if (hashMode === "pointer" && !contentRef) {
    throw new Error("content_ref is required when hash_mode='pointer'");
  }

  return computeGovernanceHash(`${resourceType}:${resourceName}:${hashable}`);
}

function computeMerkleRoot(sortedHashes) {
  if (!sortedHashes.length) {
    throw new Error("Cannot compute Merkle root of empty list");
  }
  if (sortedHashes.length === 1) {
    return sortedHashes[0];
  }

  let level = sortedHashes.slice();
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 >= level.length) {
        next.push(level[i]);
      } else {
        next.push(computeGovernanceHash(level[i] + level[i + 1]));
      }
    }
    level = next;
  }
  return level[0];
}

function buildInclusionProofs(merkleTree) {
  const leaves = (merkleTree && merkleTree.leaves) || [];
  if (!Array.isArray(leaves) || leaves.length === 0) {
    return [];
  }

  const proofs = leaves.map(() => []);
  let nodes = leaves.map((leaf, index) => ({
    hash: leaf.hash,
    leafIndexes: [index],
  }));

  while (nodes.length > 1) {
    const next = [];
    for (let i = 0; i < nodes.length; i += 2) {
      if (i + 1 >= nodes.length) {
        next.push(nodes[i]);
        continue;
      }
      const left = nodes[i];
      const right = nodes[i + 1];

      for (const leafIndex of left.leafIndexes) {
        proofs[leafIndex].push({
          sibling_hash: right.hash,
          sibling_position: "right",
        });
      }
      for (const leafIndex of right.leafIndexes) {
        proofs[leafIndex].push({
          sibling_hash: left.hash,
          sibling_position: "left",
        });
      }

      next.push({
        hash: computeGovernanceHash(left.hash + right.hash),
        leafIndexes: [...left.leafIndexes, ...right.leafIndexes],
      });
    }
    nodes = next;
  }

  return leaves.map((leaf, index) => ({
    leaf_hash: leaf.hash,
    proof_path: proofs[index],
  }));
}

function verifyInclusionProof(rootHash, leafHash, proofPath) {
  let current = String(leafHash || "").trim();
  const expectedRoot = String(rootHash || "").trim();
  if (!current || !expectedRoot) {
    return false;
  }

  for (const step of proofPath || []) {
    const siblingHash = String(step.sibling_hash || "").trim();
    const siblingPosition = String(step.sibling_position || "").trim();
    if (!siblingHash) {
      return false;
    }
    if (siblingPosition === "left") {
      current = computeGovernanceHash(siblingHash + current);
    } else if (siblingPosition === "right") {
      current = computeGovernanceHash(current + siblingHash);
    } else {
      throw new Error('Invalid sibling_position in proof step. Expected "left" or "right".');
    }
  }

  return current === expectedRoot;
}

function normalizeResource(resource) {
  if (Array.isArray(resource)) {
    return {
      resource_type: resource[0],
      resource_name: resource[1],
      content: resource[2],
      hash_mode: "content",
      content_ref: "",
    };
  }

  return {
    resource_type: resource.resource_type || resource.resourceType,
    resource_name: resource.resource_name || resource.resourceName,
    content: resource.content || "",
    hash_mode: resource.hash_mode || resource.hashMode || "content",
    content_ref: resource.content_ref || resource.contentRef || "",
  };
}

function computeMerkleGovernanceHash(resources, options = {}) {
  if (!resources || resources.length === 0) {
    throw new Error("At least one resource is required");
  }

  const normalized = resources.map(normalizeResource);
  if (normalized.length === 1) {
    const entry = normalized[0];
    if (entry.hash_mode !== "content" && entry.hash_mode !== "pointer") {
      throw new Error(`Unsupported hash_mode: ${JSON.stringify(entry.hash_mode)} (expected "content" or "pointer")`);
    }
    if (entry.hash_mode === "pointer") {
      if (!entry.content_ref) {
        throw new Error("content_ref is required when hash_mode='pointer'");
      }
      return [computeGovernanceHash(entry.content_ref), null];
    }
    return [computeGovernanceHash(entry.content), null];
  }

  const leaves = normalized.map((entry) => {
    const hash = computeLeafHash(entry.resource_type, entry.resource_name, entry.content, {
      hash_mode: entry.hash_mode,
      content_ref: entry.content_ref,
    });

    const leaf = {
      resource_type: entry.resource_type,
      resource_name: entry.resource_name,
      hash,
    };

    if (entry.hash_mode !== "content") {
      leaf.hash_mode = entry.hash_mode;
    }
    if (entry.content_ref) {
      leaf.content_ref = entry.content_ref;
    }
    return leaf;
  });

  leaves.sort((a, b) => a.hash.localeCompare(b.hash));
  const sortedHashes = leaves.map((leaf) => leaf.hash);
  const root = computeMerkleRoot(sortedHashes);

  const tree = {
    algorithm: "sha256",
    leaf_count: leaves.length,
    leaves,
  };
  if (options.include_inclusion_proofs || options.includeInclusionProofs) {
    tree.inclusion_proofs = buildInclusionProofs(tree);
  }

  return [
    root,
    tree,
  ];
}

function canonicalizeJSON(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((v) => canonicalizeJSON(v)).join(",")}]`;
  }
  const keys = Object.keys(value).sort();
  const parts = keys.map((key) => `${JSON.stringify(key)}:${canonicalizeJSON(value[key])}`);
  return `{${parts.join(",")}}`;
}

function base64url(input) {
  const buffer = Buffer.isBuffer(input) ? input : Buffer.from(input);
  return buffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

class ES256PrivateKeySigner {
  constructor(privateKeyPem, keyId = "") {
    this.privateKeyPem = privateKeyPem;
    this._keyId = keyId;
    this._alg = "ES256";
  }

  get alg() {
    return this._alg;
  }

  get key_id() {
    return this._keyId;
  }

  sign(signingInput) {
    return crypto.sign("sha256", Buffer.from(signingInput), {
      key: this.privateKeyPem,
      dsaEncoding: "ieee-p1363",
    });
  }
}

function signEventWithSigner(event, signer) {
  if (!signer || typeof signer.sign !== "function") {
    throw new Error("signer must implement sign(signingInput)");
  }
  const header = {
    alg: signer.alg || "ES256",
    typ: "JWT",
  };
  if (signer.key_id) {
    header.kid = signer.key_id;
  }

  const payloadObject = { ...(event || {}) };
  delete payloadObject.event_signature;
  delete payloadObject.signature_key_id;

  const headerB64 = base64url(Buffer.from(canonicalizeJSON(header), "utf8"));
  const payloadB64 = base64url(Buffer.from(canonicalizeJSON(payloadObject), "utf8"));
  const signingInput = `${headerB64}.${payloadB64}`;
  const signature = signer.sign(Buffer.from(signingInput, "ascii"));

  return {
    ...(event || {}),
    event_signature: `${signingInput}.${base64url(signature)}`,
    signature_key_id: signer.key_id || "",
  };
}

class RetryPolicy {
  constructor(options = {}) {
    this.maxAttempts = Number(options.maxAttempts ?? options.max_attempts ?? 3);
    this.baseDelayMs = Number(options.baseDelayMs ?? options.base_delay_ms ?? 100);
    this.maxDelayMs = Number(options.maxDelayMs ?? options.max_delay_ms ?? 2000);
  }

  delayForAttempt(attempt) {
    const base = this.baseDelayMs * 2 ** Math.max(0, attempt - 1);
    return Math.min(base, this.maxDelayMs);
  }
}

class ReliableEmitter {
  constructor(sender, options = {}) {
    if (typeof sender !== "function") {
      throw new Error("sender must be a function");
    }
    this.sender = sender;
    this.retryPolicy = options.retryPolicy || options.retry_policy || new RetryPolicy();
    this.idempotent = options.idempotent !== false;
    this.sleep =
      options.sleep ||
      ((ms) =>
        new Promise((resolve) => {
          setTimeout(resolve, ms);
        }));
    this.deliveredIds = new Set();
    this.failedEvents = [];
  }

  get pending_count() {
    return this.failedEvents.length;
  }

  async emit(event) {
    const eventId = String((event && event.event_id) || "").trim();
    if (this.idempotent && eventId && this.deliveredIds.has(eventId)) {
      return true;
    }

    let lastError = null;
    for (let attempt = 1; attempt <= this.retryPolicy.maxAttempts; attempt += 1) {
      try {
        await this.sender(event);
        if (eventId) {
          this.deliveredIds.add(eventId);
        }
        return true;
      } catch (err) {
        lastError = err;
        if (attempt < this.retryPolicy.maxAttempts) {
          await this.sleep(this.retryPolicy.delayForAttempt(attempt));
        }
      }
    }

    this.failedEvents.push({
      ...(event || {}),
      _delivery_error: String((lastError && lastError.message) || lastError || "delivery failed"),
    });
    return false;
  }

  async flushFailed(options = {}) {
    const maxItems = Number(options.maxItems ?? options.max_items ?? 1000);
    const candidates = this.failedEvents.slice(0, maxItems);
    const rest = this.failedEvents.slice(maxItems);
    this.failedEvents = [];

    let delivered = 0;
    for (const failed of candidates) {
      const retryEvent = { ...failed };
      delete retryEvent._delivery_error;
      if (await this.emit(retryEvent)) {
        delivered += 1;
      } else {
        this.failedEvents.push(failed);
      }
    }
    this.failedEvents.push(...rest);
    return {
      delivered,
      pending: this.failedEvents.length,
    };
  }
}

function createAIGPEvent(options) {
  const eventType = normalizeEventType(options.event_type || options.eventType);
  const eventCategory = normalizeEventCategory(options.event_category || options.eventCategory);
  const agentId = String(options.agent_id || options.agentId || "");
  const traceId = String(options.trace_id || options.traceId || "").trim() || randomHex(16);
  const nowIso = new Date().toISOString();
  const explicitSequence =
    hasOwn(options, "sequence_number") || hasOwn(options, "sequenceNumber")
      ? Number(options.sequence_number ?? options.sequenceNumber)
      : null;
  const sequenceNumber =
    Number.isFinite(explicitSequence) && explicitSequence >= 0
      ? explicitSequence
      : nextSequenceNumber(agentId, traceId);

  const governanceHash = String(options.governance_hash || options.governanceHash || "").trim();
  if (!governanceHash) {
    throw new Error("governance_hash is required and cannot be empty");
  }

  const event = {
    event_id: generateEventId(),
    event_type: eventType,
    event_category: eventCategory,
    event_time: nowIso,
    agent_id: agentId,
    governance_hash: governanceHash,
    trace_id: traceId,
    span_id: String(options.span_id || options.spanId || ""),
    parent_span_id: String(options.parent_span_id || options.parentSpanId || ""),
    trace_flags: String(options.trace_flags || options.traceFlags || ""),
    agent_name: String(options.agent_name || options.agentName || ""),
    org_id: String(options.org_id || options.orgId || ""),
    org_name: String(options.org_name || options.orgName || ""),
    policy_id: String(options.policy_id || options.policyId || ""),
    policy_name: String(options.policy_name || options.policyName || ""),
    policy_version: Number(options.policy_version || options.policyVersion || 0),
    prompt_id: String(options.prompt_id || options.promptId || ""),
    prompt_name: String(options.prompt_name || options.promptName || ""),
    prompt_version: Number(options.prompt_version || options.promptVersion || 0),
    hash_type: String(options.hash_type || options.hashType || "sha256"),
    data_classification: String(options.data_classification || options.dataClassification || ""),
    template_rendered: Boolean(options.template_rendered || options.templateRendered || false),
    denial_reason: String(options.denial_reason || options.denialReason || ""),
    violation_type: String(options.violation_type || options.violationType || ""),
    severity: String(options.severity || ""),
    source_ip: String(options.source_ip || options.sourceIp || ""),
    request_method: String(options.request_method || options.requestMethod || ""),
    request_path: String(options.request_path || options.requestPath || ""),
    query_hash: String(options.query_hash || options.queryHash || ""),
    previous_hash: String(options.previous_hash || options.previousHash || ""),
    annotations: options.annotations || {},
    event_signature: String(options.event_signature || options.eventSignature || ""),
    signature_key_id: String(options.signature_key_id || options.signatureKeyId || ""),
    sequence_number: sequenceNumber,
    causality_ref: String(options.causality_ref || options.causalityRef || ""),
    spec_version: String(options.spec_version || options.specVersion || "0.10.0"),
  };

  const merkleTree = options.governance_merkle_tree || options.governanceMerkleTree;
  if (merkleTree != null) {
    event.governance_merkle_tree = merkleTree;
  }

  return event;
}

function emitAIGPEvent(options) {
  options = options || {};
  const hasHash = String(options.governance_hash || options.governanceHash || "").trim() !== "";
  if (!hasHash) {
    const hashType = String(options.hash_type || options.hashType || "sha256");
    if (hashType === "merkle-sha256") {
      throw new Error("governance_hash is required when hash_type is merkle-sha256");
    }
    const content = String(options.content || "").trim();
    if (!content) {
      throw new Error("content is required when governance_hash is not provided");
    }
    options = {
      ...options,
      governance_hash: computeGovernanceHash(content, hashType),
    };
  }
  return createAIGPEvent(options);
}

function validateAIGPEvent(event) {
  const errors = [];
  const required = [
    "event_id",
    "event_type",
    "event_category",
    "event_time",
    "agent_id",
    "trace_id",
  ];

  for (const key of required) {
    if (!(key in event) || event[key] === "") {
      errors.push(`Missing required field: ${key}`);
    }
  }
  if (!Object.prototype.hasOwnProperty.call(event, "governance_hash")) {
    errors.push("Missing required field: governance_hash");
  } else if (String(event.governance_hash || "").trim() === "") {
    errors.push("governance_hash must be a non-empty string");
  }

  if (event.event_type && !EVENT_TYPE_PATTERN.test(event.event_type)) {
    errors.push("event_type must match ^[A-Z][A-Z0-9_]*$");
  }

  if (event.trace_id) {
    const traceId = String(event.trace_id);
    const hasSpan = String(event.span_id || "").trim() !== "";
    const valid = hasSpan
      ? TRACE_ID_OTEL_PATTERN.test(traceId)
      : TRACE_ID_OTEL_PATTERN.test(traceId) ||
        TRACE_ID_UUID_V4_PATTERN.test(traceId) ||
        TRACE_ID_PREFIXED_UUID_V4_PATTERN.test(traceId);
    if (!valid) {
      if (hasSpan) {
        errors.push("trace_id must be 32-char lowercase hex when span_id is present");
      } else {
        errors.push("trace_id must be 32-char lowercase hex, UUID v4, or trace-/req- prefixed UUID v4");
      }
    }
  }

  const sequence = Number(event.sequence_number);
  if (!Number.isFinite(sequence) || sequence < 1) {
    errors.push("sequence_number must be an integer >= 1");
  }

  return errors;
}

function ceTypeFromEventType(eventType) {
  return `${AIGP_TYPE_PREFIX}${normalizeEventType(eventType).toLowerCase()}`;
}

function eventTypeFromCeType(ceType) {
  if (!String(ceType).startsWith(AIGP_TYPE_PREFIX)) {
    throw new Error(`CloudEvents type ${JSON.stringify(ceType)} does not start with ${JSON.stringify(AIGP_TYPE_PREFIX)}`);
  }
  return ceType.slice(AIGP_TYPE_PREFIX.length);
}

function wrapAsCloudEvent(aigpEvent, options = {}) {
  const includeDataschema = options.include_dataschema ?? options.includeDataschema ?? true;
  const eventId = aigpEvent.event_id || "";
  const eventType = aigpEvent.event_type || "";
  const agentId = aigpEvent.agent_id || "";

  if (!eventId || !eventType || !agentId) {
    throw new Error("AIGP event must have event_id, event_type, and agent_id to wrap as CloudEvent");
  }

  const orgId = aigpEvent.org_id || "default";
  const ce = {
    specversion: CE_SPECVERSION,
    id: eventId,
    type: ceTypeFromEventType(eventType),
    source: `${AIGP_SOURCE_SCHEME}${orgId}/${agentId}`,
    datacontenttype: "application/json",
    aigpagentid: agentId,
    data: aigpEvent,
  };

  if (aigpEvent.event_time) {
    ce.time = aigpEvent.event_time;
  }
  if (includeDataschema) {
    ce.dataschema = AIGP_DATA_SCHEMA;
  }

  const subject = aigpEvent.policy_name || aigpEvent.prompt_name || "";
  if (subject) {
    ce.subject = subject;
  }

  if (orgId !== "default") {
    ce.aigporgid = orgId;
  }
  if (aigpEvent.event_category) {
    ce.aigpcategory = aigpEvent.event_category;
  }
  if (aigpEvent.data_classification) {
    ce.aigpclassification = aigpEvent.data_classification;
  }
  if (aigpEvent.severity) {
    ce.aigpseverity = aigpEvent.severity;
  }
  if (aigpEvent.hash_type) {
    ce.aigphashtype = aigpEvent.hash_type;
  }

  return ce;
}

function unwrapFromCloudEvent(ce) {
  if ((ce.specversion || "") !== CE_SPECVERSION) {
    throw new Error(`Unsupported CloudEvents specversion: ${JSON.stringify(ce.specversion)}`);
  }

  if (!String(ce.type || "").startsWith(AIGP_TYPE_PREFIX)) {
    throw new Error(`CloudEvents type ${JSON.stringify(ce.type)} does not start with ${JSON.stringify(AIGP_TYPE_PREFIX)} — not an AIGP event`);
  }

  if (ce.data == null || typeof ce.data !== "object" || Array.isArray(ce.data)) {
    throw new Error("CloudEvents 'data' must be an object");
  }

  return ce.data;
}

function buildCEHeaders(aigpEvent, options = {}) {
  const prefix = options.prefix || "ce-";
  const eventId = aigpEvent.event_id || "";
  const eventType = aigpEvent.event_type || "";
  const agentId = aigpEvent.agent_id || "";
  const orgId = aigpEvent.org_id || "default";

  const headers = {
    [`${prefix}specversion`]: CE_SPECVERSION,
    [`${prefix}id`]: String(eventId),
    [`${prefix}type`]: ceTypeFromEventType(eventType),
    [`${prefix}source`]: `${AIGP_SOURCE_SCHEME}${orgId}/${agentId}`,
    [`${prefix}aigpagentid`]: String(agentId),
  };

  if (aigpEvent.event_time) {
    headers[`${prefix}time`] = aigpEvent.event_time;
  }
  if (orgId !== "default") {
    headers[`${prefix}aigporgid`] = String(orgId);
  }
  if (aigpEvent.event_category) {
    headers[`${prefix}aigpcategory`] = String(aigpEvent.event_category);
  }
  if (aigpEvent.data_classification) {
    headers[`${prefix}aigpclassification`] = String(aigpEvent.data_classification);
  }
  if (aigpEvent.severity) {
    headers[`${prefix}aigpseverity`] = String(aigpEvent.severity);
  }
  if (aigpEvent.hash_type) {
    headers[`${prefix}aigphashtype`] = String(aigpEvent.hash_type);
  }

  return headers;
}

module.exports = {
  VERSION,
  CE_SPECVERSION,
  AIGP_TYPE_PREFIX,
  AIGP_SOURCE_SCHEME,
  AIGP_DATA_SCHEMA,
  normalizeEventType,
  normalizeEventCategory,
  computeGovernanceHash,
  computeLeafHash,
  computeMerkleGovernanceHash,
  buildInclusionProofs,
  verifyInclusionProof,
  createAIGPEvent,
  emitAIGPEvent,
  validateAIGPEvent,
  ES256PrivateKeySigner,
  signEventWithSigner,
  RetryPolicy,
  ReliableEmitter,
  ceTypeFromEventType,
  eventTypeFromCeType,
  wrapAsCloudEvent,
  unwrapFromCloudEvent,
  buildCEHeaders,
};
