package aigp

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestNormalizeEventType(t *testing.T) {
	got, err := NormalizeEventType("governance.policy.delivered")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "INJECT_SUCCESS" {
		t.Fatalf("expected INJECT_SUCCESS, got %q", got)
	}

	custom, err := NormalizeEventType("myplatform.audit.login")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if custom != "MYPLATFORM_AUDIT_LOGIN" {
		t.Fatalf("expected MYPLATFORM_AUDIT_LOGIN, got %q", custom)
	}
}

func TestCreateAndValidateAIGPEvent(t *testing.T) {
	governanceHash, err := ComputeGovernanceHash("policy", "sha256")
	if err != nil {
		t.Fatalf("unexpected hash error: %v", err)
	}

	event, err := CreateAIGPEvent(CreateEventOptions{
		EventType:      "governance.policy.delivered",
		EventCategory:  "Inject",
		AgentID:        "agent.test",
		GovernanceHash: governanceHash,
	})
	if err != nil {
		t.Fatalf("unexpected create error: %v", err)
	}
	if event.EventType != "INJECT_SUCCESS" {
		t.Fatalf("expected normalized event type, got %q", event.EventType)
	}
	if event.EventCategory != "inject" {
		t.Fatalf("expected normalized event category, got %q", event.EventCategory)
	}
	if event.TraceID == "" {
		t.Fatal("trace_id should be auto-generated")
	}
	if event.SequenceNumber < 1 {
		t.Fatalf("expected auto sequence_number >= 1, got %d", event.SequenceNumber)
	}
	if event.SpecVersion != "0.10.0" {
		t.Fatalf("expected default spec_version 0.10.0, got %q", event.SpecVersion)
	}

	errs := ValidateAIGPEvent(event)
	if len(errs) != 0 {
		t.Fatalf("expected no validation errors, got %v", errs)
	}
}

func TestCreateAIGPEventAutoIncrementsSequenceNumberPerScope(t *testing.T) {
	traceID := "trace-aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	e1, err := CreateAIGPEvent(CreateEventOptions{
		EventType:      "INJECT_SUCCESS",
		EventCategory:  "inject",
		AgentID:        "agent.test",
		TraceID:        traceID,
		GovernanceHash: "abc",
	})
	if err != nil {
		t.Fatalf("unexpected create error: %v", err)
	}
	e2, err := CreateAIGPEvent(CreateEventOptions{
		EventType:      "PROMPT_USED",
		EventCategory:  "prompt",
		AgentID:        "agent.test",
		TraceID:        traceID,
		GovernanceHash: "def",
	})
	if err != nil {
		t.Fatalf("unexpected create error: %v", err)
	}
	if e2.SequenceNumber != e1.SequenceNumber+1 {
		t.Fatalf("expected sequence increment, got %d then %d", e1.SequenceNumber, e2.SequenceNumber)
	}
}

func TestEmitAIGPEventComputesGovernanceHash(t *testing.T) {
	event, err := EmitAIGPEvent(CreateEventOptions{
		EventType:     "INJECT_SUCCESS",
		EventCategory: "inject",
		AgentID:       "agent.test",
	}, "Max position: $10M")
	if err != nil {
		t.Fatalf("unexpected emit error: %v", err)
	}
	if event.GovernanceHash == "" {
		t.Fatal("expected computed governance_hash")
	}
	expected, _ := ComputeGovernanceHash("Max position: $10M", "sha256")
	if event.GovernanceHash != expected {
		t.Fatalf("expected governance_hash %q, got %q", expected, event.GovernanceHash)
	}
}

func TestEmitAIGPEventRequiresContentWhenHashMissing(t *testing.T) {
	_, err := EmitAIGPEvent(CreateEventOptions{
		EventType:     "INJECT_SUCCESS",
		EventCategory: "inject",
		AgentID:       "agent.test",
	}, "")
	if err == nil {
		t.Fatal("expected error when content and governance_hash are both missing")
	}
}

func TestComputeMerkleGovernanceHash(t *testing.T) {
	singleRoot, singleTree, err := ComputeMerkleGovernanceHash([]Resource{
		{ResourceType: "policy", ResourceName: "policy.limits", Content: "Max $10M"},
	})
	if err != nil {
		t.Fatalf("unexpected merkle error: %v", err)
	}
	if singleTree != nil {
		t.Fatal("expected nil tree for single resource")
	}
	expectedSingle, _ := ComputeGovernanceHash("Max $10M", "sha256")
	if singleRoot != expectedSingle {
		t.Fatalf("single root mismatch: expected %q, got %q", expectedSingle, singleRoot)
	}

	root, tree, err := ComputeMerkleGovernanceHash([]Resource{
		{ResourceType: "policy", ResourceName: "policy.limits", Content: "Max $10M"},
		{ResourceType: "prompt", ResourceName: "prompt.system", Content: "You are a trading assistant"},
	})
	if err != nil {
		t.Fatalf("unexpected merkle error: %v", err)
	}
	if root == "" {
		t.Fatal("expected non-empty merkle root")
	}
	if tree == nil || tree.LeafCount != 2 {
		t.Fatalf("expected tree with 2 leaves, got %+v", tree)
	}
}

func TestComputeMerkleGovernanceHashWithProofs(t *testing.T) {
	root, tree, err := ComputeMerkleGovernanceHashWithProofs([]Resource{
		{ResourceType: "policy", ResourceName: "policy.limits", Content: "Max $10M"},
		{ResourceType: "prompt", ResourceName: "prompt.system", Content: "You are a trading assistant"},
		{ResourceType: "tool", ResourceName: "tool.search", Content: "{\"scope\":\"read\"}"},
	}, true)
	if err != nil {
		t.Fatalf("unexpected merkle error: %v", err)
	}
	if tree == nil || len(tree.InclusionProofs) != tree.LeafCount {
		t.Fatalf("expected inclusion proofs for all leaves, got %+v", tree)
	}

	for _, proof := range tree.InclusionProofs {
		ok, verifyErr := VerifyInclusionProof(root, proof.LeafHash, proof.ProofPath)
		if verifyErr != nil {
			t.Fatalf("unexpected verify error: %v", verifyErr)
		}
		if !ok {
			t.Fatalf("expected proof to verify for leaf %s", proof.LeafHash)
		}
	}
}

func TestVerifyInclusionProofTamperFails(t *testing.T) {
	root, tree, err := ComputeMerkleGovernanceHashWithProofs([]Resource{
		{ResourceType: "policy", ResourceName: "policy.limits", Content: "Max $10M"},
		{ResourceType: "prompt", ResourceName: "prompt.system", Content: "You are a trading assistant"},
		{ResourceType: "tool", ResourceName: "tool.search", Content: "{\"scope\":\"read\"}"},
	}, true)
	if err != nil {
		t.Fatalf("unexpected merkle error: %v", err)
	}
	sample := tree.InclusionProofs[0]
	tampered := append([]MerkleProofStep{}, sample.ProofPath...)
	if len(tampered) > 0 {
		tampered[0].SiblingHash = strings.Repeat("0", 64)
	}
	ok, verifyErr := VerifyInclusionProof(root, sample.LeafHash, tampered)
	if verifyErr != nil {
		t.Fatalf("unexpected verify error: %v", verifyErr)
	}
	if ok {
		t.Fatal("expected tampered proof to fail verification")
	}
}

func TestSignEventWithSigner(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
	})
	signer, err := NewES256PrivateKeySigner(privateKeyPEM, "key.test")
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	event, err := CreateAIGPEvent(CreateEventOptions{
		EventType:      "INJECT_SUCCESS",
		EventCategory:  "inject",
		AgentID:        "agent.test",
		TraceID:        strings.Repeat("a", 32),
		GovernanceHash: ComputeHashMust("policy"),
	})
	if err != nil {
		t.Fatalf("create event: %v", err)
	}
	signed, err := SignEventWithSigner(event, signer)
	if err != nil {
		t.Fatalf("sign event: %v", err)
	}
	if signed.SignatureKeyID != "key.test" || signed.EventSignature == "" {
		t.Fatalf("expected populated signature fields, got %+v", signed)
	}

	parts := strings.Split(signed.EventSignature, ".")
	if len(parts) != 3 {
		t.Fatalf("expected JWS compact signature, got %q", signed.EventSignature)
	}
	signingInput := []byte(parts[0] + "." + parts[1])
	signature, decodeErr := decodeBase64URL(parts[2])
	if decodeErr != nil {
		t.Fatalf("decode signature: %v", decodeErr)
	}
	if len(signature) != 64 {
		t.Fatalf("expected 64-byte ES256 signature, got %d", len(signature))
	}
	digest := sha256.Sum256(signingInput)
	r := signature[:32]
	s := signature[32:]
	if !ecdsa.Verify(&privateKey.PublicKey, digest[:], newBigInt(r), newBigInt(s)) {
		t.Fatal("signature verification failed")
	}
}

func TestReliableEmitterRetriesAndDeduplicates(t *testing.T) {
	attempts := 0
	sent := []string{}
	emitter := NewReliableEmitter(func(event AIGPEvent) error {
		attempts++
		if attempts < 3 {
			return errors.New("transient")
		}
		sent = append(sent, event.EventID)
		return nil
	}, RetryPolicy{
		MaxAttempts: 3,
		BaseDelay:   0,
		MaxDelay:    0,
	}, true, func(_ time.Duration) {})

	event := AIGPEvent{EventID: "evt-1"}
	if !emitter.Emit(event) {
		t.Fatal("expected emit success")
	}
	if attempts != 3 {
		t.Fatalf("expected 3 attempts, got %d", attempts)
	}
	if len(sent) != 1 || sent[0] != "evt-1" {
		t.Fatalf("unexpected sent events: %+v", sent)
	}
	if !emitter.Emit(event) {
		t.Fatal("expected deduplicated emit success")
	}
	if len(sent) != 1 {
		t.Fatalf("expected no duplicate sends, got %+v", sent)
	}
}

func ComputeHashMust(content string) string {
	hash, _ := ComputeGovernanceHash(content, "sha256")
	return hash
}

func decodeBase64URL(value string) ([]byte, error) {
	padded := value
	for len(padded)%4 != 0 {
		padded += "="
	}
	return base64.URLEncoding.DecodeString(padded)
}

func newBigInt(buf []byte) *big.Int {
	out := new(big.Int)
	out.SetBytes(buf)
	return out
}

func TestHashModeValidation(t *testing.T) {
	if _, err := ComputeLeafHash("policy", "policy.limits", "Max $10M", "bogus", ""); err == nil {
		t.Fatal("expected error for invalid hash_mode")
	}
	if _, _, err := ComputeMerkleGovernanceHash([]Resource{
		{ResourceType: "policy", ResourceName: "policy.limits", HashMode: "pointer"},
	}); err == nil {
		t.Fatal("expected error when hash_mode=pointer and content_ref is missing")
	}
}

func TestCloudEventHelpers(t *testing.T) {
	governanceHash, err := ComputeGovernanceHash("policy", "sha256")
	if err != nil {
		t.Fatalf("unexpected hash error: %v", err)
	}

	event, err := CreateAIGPEvent(CreateEventOptions{
		EventType:      "INJECT_SUCCESS",
		EventCategory:  "inject",
		AgentID:        "agent.test",
		OrgID:          "org.acme",
		PolicyName:     "policy.limits",
		GovernanceHash: governanceHash,
	})
	if err != nil {
		t.Fatalf("unexpected create error: %v", err)
	}

	ce, err := WrapAsCloudEvent(event, true)
	if err != nil {
		t.Fatalf("unexpected wrap error: %v", err)
	}
	if ce["type"] != "org.aigp.v1.inject_success" {
		t.Fatalf("unexpected ce type: %v", ce["type"])
	}
	if ce["source"] != "aigp://org.acme/agent.test" {
		t.Fatalf("unexpected source: %v", ce["source"])
	}
	if ce["subject"] != "policy.limits" {
		t.Fatalf("unexpected subject: %v", ce["subject"])
	}

	headers, err := BuildCEHeaders(event, "ce-")
	if err != nil {
		t.Fatalf("unexpected header error: %v", err)
	}
	if headers["ce-type"] != "org.aigp.v1.inject_success" {
		t.Fatalf("unexpected ce-type header: %s", headers["ce-type"])
	}
	if headers["ce-aigpagentid"] != "agent.test" {
		t.Fatalf("unexpected ce-aigpagentid header: %s", headers["ce-aigpagentid"])
	}
}

func TestCreateRejectsEmptyGovernanceHash(t *testing.T) {
	_, err := CreateAIGPEvent(CreateEventOptions{
		EventType:      "AGENT_REGISTERED",
		EventCategory:  "agent-lifecycle",
		AgentID:        "agent.test",
		TraceID:        "trace-550e8400-e29b-41d4-a716-446655440000",
		GovernanceHash: "",
	})
	if err == nil {
		t.Fatal("expected create error for empty governance_hash")
	}
}

func TestValidateRequiresW3CTraceIDWhenSpanPresent(t *testing.T) {
	event, err := CreateAIGPEvent(CreateEventOptions{
		EventType:      "INJECT_SUCCESS",
		EventCategory:  "inject",
		AgentID:        "agent.test",
		GovernanceHash: "abc",
		TraceID:        "trace-550e8400-e29b-41d4-a716-446655440000",
		SpanID:         "00f067aa0ba902b7",
	})
	if err != nil {
		t.Fatalf("unexpected create error: %v", err)
	}
	errs := ValidateAIGPEvent(event)
	if len(errs) == 0 {
		t.Fatal("expected validation error for non-W3C trace_id with span_id")
	}
}

func TestConformanceFixtures(t *testing.T) {
	path := filepath.Join("..", "conformance", "validation-fixtures.tsv")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open fixture file: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	headers := []string{}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if len(headers) == 0 {
			headers = strings.Split(line, "\t")
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != len(headers) {
			t.Fatalf("invalid fixture row: %q", line)
		}
		row := map[string]string{}
		for i, h := range headers {
			row[h] = parts[i]
		}

		isValid := false
		event, err := CreateAIGPEvent(CreateEventOptions{
			EventType:      row["event_type"],
			EventCategory:  row["event_category"],
			AgentID:        "agent.test",
			TraceID:        row["trace_id"],
			SpanID:         row["span_id"],
			GovernanceHash: row["governance_hash"],
		})
		if err == nil {
			if row["sequence_number"] != "" {
				sequence, convErr := strconv.ParseInt(row["sequence_number"], 10, 64)
				if convErr != nil {
					t.Fatalf("invalid sequence_number in fixture %s: %v", row["case_id"], convErr)
				}
				event.SequenceNumber = sequence
			}
			event.CausalityRef = row["causality_ref"]
			isValid = len(ValidateAIGPEvent(event)) == 0
		}
		expectValid := row["expect_valid"] == "true"
		if isValid != expectValid {
			t.Fatalf("fixture %s failed: expected valid=%v got valid=%v", row["case_id"], expectValid, isValid)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan fixture file: %v", err)
	}
}
