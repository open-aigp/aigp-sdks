const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const sdk = require("../index.js");

function loadConformanceFixtures() {
  const fixturePath = path.resolve(__dirname, "../../conformance/validation-fixtures.tsv");
  const rows = fs.readFileSync(fixturePath, "utf8").trim().split("\n");
  const header = rows.shift().split("\t");
  return rows.map((line) => {
    const values = line.split("\t");
    const out = {};
    for (let i = 0; i < header.length; i += 1) {
      out[header[i]] = values[i] || "";
    }
    out.expect_valid = out.expect_valid === "true";
    return out;
  });
}

test("normalizeEventType maps legacy aliases", () => {
  assert.equal(sdk.normalizeEventType("governance.policy.delivered"), "INJECT_SUCCESS");
  assert.equal(sdk.normalizeEventType("governance.prompt.denied"), "PROMPT_DENIED");
});

test("normalizeEventType normalizes custom names", () => {
  assert.equal(sdk.normalizeEventType("myplatform.audit.login"), "MYPLATFORM_AUDIT_LOGIN");
});

test("createAIGPEvent returns spec-conformant core fields", () => {
  const event = sdk.createAIGPEvent({
    event_type: "governance.policy.delivered",
    event_category: "Inject",
    agent_id: "agent.test",
    governance_hash: sdk.computeGovernanceHash("policy"),
  });

  assert.equal(event.event_type, "INJECT_SUCCESS");
  assert.equal(event.event_category, "inject");
  assert.match(event.trace_id, /^[a-f0-9]{32}$/);
  assert.ok(event.sequence_number >= 1);
  assert.equal(event.spec_version, "0.10.0");
  assert.equal(sdk.validateAIGPEvent(event).length, 0);
});

test("createAIGPEvent auto-increments sequence_number per (agent_id, trace_id)", () => {
  const traceId = "trace-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const e1 = sdk.createAIGPEvent({
    event_type: "INJECT_SUCCESS",
    event_category: "inject",
    agent_id: "agent.test",
    trace_id: traceId,
    governance_hash: sdk.computeGovernanceHash("policy-v1"),
  });
  const e2 = sdk.createAIGPEvent({
    event_type: "PROMPT_USED",
    event_category: "prompt",
    agent_id: "agent.test",
    trace_id: traceId,
    governance_hash: sdk.computeGovernanceHash("prompt-v1"),
  });

  assert.equal(e2.sequence_number, e1.sequence_number + 1);
});

test("emitAIGPEvent computes governance hash from content", () => {
  const event = sdk.emitAIGPEvent({
    event_type: "INJECT_SUCCESS",
    event_category: "inject",
    agent_id: "agent.test",
    content: "Max position: $10M",
  });
  assert.ok(event.governance_hash);
  assert.equal(event.governance_hash, sdk.computeGovernanceHash("Max position: $10M"));
});

test("emitAIGPEvent requires content when governance_hash is not provided", () => {
  assert.throws(
    () => sdk.emitAIGPEvent({ event_type: "INJECT_SUCCESS", event_category: "inject", agent_id: "agent.test" }),
    /content is required/
  );
});

test("createAIGPEvent accepts camelCase option keys", () => {
  const event = sdk.createAIGPEvent({
    eventType: "governance.policy.denied",
    eventCategory: "Inject",
    agentId: "agent.test",
    governanceHash: sdk.computeGovernanceHash("policy"),
  });

  assert.equal(event.event_type, "INJECT_DENIED");
  assert.equal(event.agent_id, "agent.test");
  assert.equal(sdk.validateAIGPEvent(event).length, 0);
});

test("computeMerkleGovernanceHash handles single and multi resource", () => {
  const [singleRoot, singleTree] = sdk.computeMerkleGovernanceHash([
    ["policy", "policy.limits", "Max $10M"],
  ]);
  assert.equal(singleTree, null);
  assert.equal(singleRoot, sdk.computeGovernanceHash("Max $10M"));

  const [root, tree] = sdk.computeMerkleGovernanceHash([
    ["policy", "policy.limits", "Max $10M"],
    ["prompt", "prompt.system", "You are a trading assistant"],
  ]);
  assert.ok(root);
  assert.ok(tree);
  assert.equal(tree.leaf_count, 2);
});

test("computeMerkleGovernanceHash can include inclusion_proofs", () => {
  const [root, tree] = sdk.computeMerkleGovernanceHash(
    [
      ["policy", "policy.limits", "Max $10M"],
      ["prompt", "prompt.system", "You are a trading assistant"],
      ["tool", "tool.search", '{"scope":"read"}'],
    ],
    { include_inclusion_proofs: true }
  );
  assert.ok(tree);
  assert.equal(Array.isArray(tree.inclusion_proofs), true);
  assert.equal(tree.inclusion_proofs.length, tree.leaf_count);
  for (const proofEntry of tree.inclusion_proofs) {
    assert.equal(
      sdk.verifyInclusionProof(root, proofEntry.leaf_hash, proofEntry.proof_path),
      true
    );
  }
});

test("verifyInclusionProof rejects tampered proof", () => {
  const [root, tree] = sdk.computeMerkleGovernanceHash(
    [
      ["policy", "policy.a", "A"],
      ["prompt", "prompt.b", "B"],
      ["tool", "tool.c", "C"],
    ],
    { include_inclusion_proofs: true }
  );
  const sample = tree.inclusion_proofs[0];
  const tampered = sample.proof_path.map((step, index) =>
    index === 0 ? { ...step, sibling_hash: "0".repeat(64) } : step
  );
  assert.equal(sdk.verifyInclusionProof(root, sample.leaf_hash, tampered), false);
});

test("computeLeafHash validates hash_mode", () => {
  assert.throws(
    () => sdk.computeLeafHash("policy", "policy.limits", "Max $10M", { hash_mode: "bogus" }),
    /Unsupported hash_mode/
  );
  assert.throws(
    () => sdk.computeMerkleGovernanceHash([{ resource_type: "policy", resource_name: "policy.limits", hash_mode: "pointer" }]),
    /content_ref is required/
  );
});

test("signEventWithSigner signs event with pluggable signer", () => {
  const { generateKeyPairSync, verify } = require("node:crypto");
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const privatePem = privateKey.export({ type: "pkcs8", format: "pem" });

  const signer = new sdk.ES256PrivateKeySigner(privatePem, "key.test-1");
  const event = sdk.createAIGPEvent({
    event_type: "INJECT_SUCCESS",
    event_category: "inject",
    agent_id: "agent.test",
    governance_hash: sdk.computeGovernanceHash("policy"),
    trace_id: "a".repeat(32),
  });
  const signed = sdk.signEventWithSigner(event, signer);
  assert.equal(signed.signature_key_id, "key.test-1");
  assert.ok(signed.event_signature);

  const [headerB64, payloadB64, sigB64] = signed.event_signature.split(".");
  const input = Buffer.from(`${headerB64}.${payloadB64}`, "ascii");
  const sig = Buffer.from(sigB64.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  const ok = verify("sha256", input, { key: publicKey, dsaEncoding: "ieee-p1363" }, sig);
  assert.equal(ok, true);
});

test("ReliableEmitter retries and deduplicates by event_id", async () => {
  let attempts = 0;
  const sent = [];
  const emitter = new sdk.ReliableEmitter(
    async (event) => {
      attempts += 1;
      if (attempts < 3) {
        throw new Error("transient");
      }
      sent.push(event.event_id);
    },
    {
      retryPolicy: new sdk.RetryPolicy({ maxAttempts: 3, baseDelayMs: 0, maxDelayMs: 0 }),
      sleep: async () => {},
    }
  );

  const event = { event_id: "evt-1" };
  assert.equal(await emitter.emit(event), true);
  assert.equal(attempts, 3);
  assert.deepEqual(sent, ["evt-1"]);
  assert.equal(await emitter.emit(event), true);
  assert.deepEqual(sent, ["evt-1"]);
});

test("CloudEvents helpers produce expected mappings", () => {
  const event = sdk.createAIGPEvent({
    event_type: "INJECT_SUCCESS",
    event_category: "inject",
    agent_id: "agent.test",
    org_id: "org.acme",
    policy_name: "policy.limits",
    governance_hash: sdk.computeGovernanceHash("policy"),
  });

  const ce = sdk.wrapAsCloudEvent(event);
  assert.equal(ce.type, "org.aigp.v1.inject_success");
  assert.equal(ce.source, "aigp://org.acme/agent.test");
  assert.equal(ce.subject, "policy.limits");

  const headers = sdk.buildCEHeaders(event);
  assert.equal(headers["ce-type"], "org.aigp.v1.inject_success");
  assert.equal(headers["ce-aigpagentid"], "agent.test");
});

test("createAIGPEvent rejects empty governance_hash", () => {
  assert.throws(
    () =>
      sdk.createAIGPEvent({
        event_type: "AGENT_REGISTERED",
        event_category: "agent-lifecycle",
        agent_id: "agent.test",
        governance_hash: "",
        trace_id: "trace-550e8400-e29b-41d4-a716-446655440000",
      }),
    /governance_hash is required and cannot be empty/
  );
});

test("validator requires W3C trace_id when span_id is present", () => {
  const event = sdk.createAIGPEvent({
    event_type: "INJECT_SUCCESS",
    event_category: "inject",
    agent_id: "agent.test",
    governance_hash: sdk.computeGovernanceHash("policy"),
    trace_id: "trace-550e8400-e29b-41d4-a716-446655440000",
    span_id: "00f067aa0ba902b7",
  });
  const errors = sdk.validateAIGPEvent(event);
  assert.ok(errors.some((msg) => msg.includes("trace_id must be 32-char lowercase hex when span_id is present")));
});

test("conformance fixtures", () => {
  for (const row of loadConformanceFixtures()) {
    let isValid = false;
    try {
      const event = sdk.createAIGPEvent({
        event_type: row.event_type,
        event_category: row.event_category,
        agent_id: "agent.test",
        trace_id: row.trace_id,
        span_id: row.span_id,
        governance_hash: row.governance_hash,
        sequence_number: Number(row.sequence_number || 0),
        causality_ref: row.causality_ref || "",
      });
      isValid = sdk.validateAIGPEvent(event).length === 0;
    } catch {
      isValid = false;
    }
    assert.equal(isValid, row.expect_valid, `fixture failed: ${row.case_id}`);
  }
});
