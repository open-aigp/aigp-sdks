package aigp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Version is the AIGP SDK version.
const Version = "0.1.0"

const (
	CESpecVersion    = "1.0"
	AIGPTypePrefix   = "org.aigp.v1."
	AIGPSourceScheme = "aigp://"
	AIGPDataSchema   = "https://open-aigp.org/schema/aigp-event.schema.json"
)

var (
	resourceTypePattern          = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)
	eventTypePattern             = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	traceIDOtelPattern           = regexp.MustCompile(`^[a-f0-9]{32}$`)
	traceIDUUIDV4Pattern         = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	traceIDPrefixedUUIDV4Pattern = regexp.MustCompile(`(?i)^(trace|req)-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	sequenceMu                   sync.Mutex
	sequenceCounters             = map[string]int64{}
)

var eventTypeAliases = map[string]string{
	"governance.policy.delivered":    "INJECT_SUCCESS",
	"governance.policy.denied":       "INJECT_DENIED",
	"governance.prompt.delivered":    "PROMPT_USED",
	"governance.prompt.denied":       "PROMPT_DENIED",
	"governance.policy.violation":    "POLICY_VIOLATION",
	"governance.a2a.call":            "A2A_CALL",
	"governance.tool.invoked":        "TOOL_INVOKED",
	"governance.tool.denied":         "TOOL_DENIED",
	"governance.boundary.unverified": "UNVERIFIED_BOUNDARY",
	"governance.inference.started":   "INFERENCE_STARTED",
	"governance.inference.completed": "INFERENCE_COMPLETED",
	"governance.inference.blocked":   "INFERENCE_BLOCKED",
	"governance.model.loaded":        "MODEL_LOADED",
	"governance.model.switched":      "MODEL_SWITCHED",
	"governance.memory.read":         "MEMORY_READ",
	"governance.memory.written":      "MEMORY_WRITTEN",
	"governance.proof":               "GOVERNANCE_PROOF",
	"governance.proof.delivered":     "GOVERNANCE_PROOF",
}

type MerkleLeaf struct {
	ResourceType string `json:"resource_type"`
	ResourceName string `json:"resource_name"`
	Hash         string `json:"hash"`
	HashMode     string `json:"hash_mode,omitempty"`
	ContentRef   string `json:"content_ref,omitempty"`
}

type MerkleProofStep struct {
	SiblingHash     string `json:"sibling_hash"`
	SiblingPosition string `json:"sibling_position"`
}

type MerkleInclusionProof struct {
	LeafHash  string            `json:"leaf_hash"`
	ProofPath []MerkleProofStep `json:"proof_path"`
}

type GovernanceMerkleTree struct {
	Algorithm       string                 `json:"algorithm"`
	LeafCount       int                    `json:"leaf_count"`
	Leaves          []MerkleLeaf           `json:"leaves"`
	InclusionProofs []MerkleInclusionProof `json:"inclusion_proofs,omitempty"`
}

type Resource struct {
	ResourceType string
	ResourceName string
	Content      string
	HashMode     string
	ContentRef   string
}

type AIGPEvent struct {
	EventID              string                `json:"event_id"`
	EventType            string                `json:"event_type"`
	EventCategory        string                `json:"event_category"`
	EventTime            string                `json:"event_time"`
	AgentID              string                `json:"agent_id"`
	GovernanceHash       string                `json:"governance_hash"`
	TraceID              string                `json:"trace_id"`
	SpanID               string                `json:"span_id"`
	ParentSpanID         string                `json:"parent_span_id"`
	TraceFlags           string                `json:"trace_flags"`
	AgentName            string                `json:"agent_name"`
	OrgID                string                `json:"org_id"`
	OrgName              string                `json:"org_name"`
	PolicyID             string                `json:"policy_id"`
	PolicyName           string                `json:"policy_name"`
	PolicyVersion        int                   `json:"policy_version"`
	PromptID             string                `json:"prompt_id"`
	PromptName           string                `json:"prompt_name"`
	PromptVersion        int                   `json:"prompt_version"`
	HashType             string                `json:"hash_type"`
	DataClassification   string                `json:"data_classification"`
	TemplateRendered     bool                  `json:"template_rendered"`
	DenialReason         string                `json:"denial_reason"`
	ViolationType        string                `json:"violation_type"`
	Severity             string                `json:"severity"`
	SourceIP             string                `json:"source_ip"`
	RequestMethod        string                `json:"request_method"`
	RequestPath          string                `json:"request_path"`
	QueryHash            string                `json:"query_hash"`
	PreviousHash         string                `json:"previous_hash"`
	Annotations          map[string]any        `json:"annotations"`
	EventSignature       string                `json:"event_signature"`
	SignatureKeyID       string                `json:"signature_key_id"`
	SequenceNumber       int64                 `json:"sequence_number"`
	CausalityRef         string                `json:"causality_ref"`
	SpecVersion          string                `json:"spec_version"`
	GovernanceMerkleTree *GovernanceMerkleTree `json:"governance_merkle_tree,omitempty"`
}

type CreateEventOptions struct {
	EventType            string
	EventCategory        string
	AgentID              string
	TraceID              string
	GovernanceHash       string
	SpanID               string
	ParentSpanID         string
	TraceFlags           string
	AgentName            string
	OrgID                string
	OrgName              string
	PolicyID             string
	PolicyName           string
	PolicyVersion        int
	PromptID             string
	PromptName           string
	PromptVersion        int
	HashType             string
	DataClassification   string
	TemplateRendered     bool
	DenialReason         string
	ViolationType        string
	Severity             string
	SourceIP             string
	RequestMethod        string
	RequestPath          string
	QueryHash            string
	PreviousHash         string
	Annotations          map[string]any
	EventSignature       string
	SignatureKeyID       string
	SequenceNumber       int64
	CausalityRef         string
	SpecVersion          string
	GovernanceMerkleTree *GovernanceMerkleTree
}

type EventSigner interface {
	Algorithm() string
	KeyID() string
	Sign(signingInput []byte) ([]byte, error)
}

type ES256PrivateKeySigner struct {
	privateKey *ecdsa.PrivateKey
	keyID      string
}

func NewES256PrivateKeySigner(privateKeyPEM []byte, keyID string) (*ES256PrivateKeySigner, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, errors.New("invalid private key PEM")
	}

	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	privateKey, ok := keyAny.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key must be ECDSA (P-256)")
	}
	if privateKey.Curve != elliptic.P256() {
		return nil, errors.New("private key curve must be P-256 for ES256")
	}

	return &ES256PrivateKeySigner{
		privateKey: privateKey,
		keyID:      keyID,
	}, nil
}

func (s *ES256PrivateKeySigner) Algorithm() string {
	return "ES256"
}

func (s *ES256PrivateKeySigner) KeyID() string {
	return s.keyID
}

func (s *ES256PrivateKeySigner) Sign(signingInput []byte) ([]byte, error) {
	digest := sha256.Sum256(signingInput)
	r, sv, err := ecdsa.Sign(rand.Reader, s.privateKey, digest[:])
	if err != nil {
		return nil, err
	}

	rb := leftPad32(r.Bytes())
	sb := leftPad32(sv.Bytes())
	return append(rb, sb...), nil
}

func randomHex(bytes int) (string, error) {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func generateEventID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	buf[6] = (buf[6] & 0x0f) | 0x40
	buf[8] = (buf[8] & 0x3f) | 0x80
	hexStr := hex.EncodeToString(buf)
	return fmt.Sprintf("%s-%s-%s-%s-%s", hexStr[0:8], hexStr[8:12], hexStr[12:16], hexStr[16:20], hexStr[20:32]), nil
}

func NormalizeEventType(eventType string) (string, error) {
	raw := strings.TrimSpace(eventType)
	if raw == "" {
		return "", errors.New("event_type must be a non-empty string")
	}

	mapped, ok := eventTypeAliases[raw]
	if !ok {
		mapped = raw
	}
	if eventTypePattern.MatchString(mapped) {
		return mapped, nil
	}

	normalized := strings.ToUpper(regexp.MustCompile(`[^A-Za-z0-9]+`).ReplaceAllString(mapped, "_"))
	normalized = strings.Trim(normalized, "_")
	if normalized == "" || !eventTypePattern.MatchString(normalized) {
		return "", fmt.Errorf("event_type %q cannot be normalized to valid UPPER_SNAKE_CASE", eventType)
	}
	return normalized, nil
}

func NormalizeEventCategory(eventCategory string) string {
	raw := strings.TrimSpace(strings.ToLower(eventCategory))
	if raw == "" {
		return "governance"
	}
	raw = strings.ReplaceAll(raw, "_", "-")
	raw = regexp.MustCompile(`[^a-z0-9-]+`).ReplaceAllString(raw, "-")
	raw = strings.Trim(raw, "-")
	if raw == "" {
		return "governance"
	}
	return raw
}

func ComputeGovernanceHash(content string, algorithm string) (string, error) {
	if algorithm == "" {
		algorithm = "sha256"
	}
	b := []byte(content)
	switch algorithm {
	case "sha256":
		h := sha256.Sum256(b)
		return hex.EncodeToString(h[:]), nil
	case "sha384":
		h := sha512.Sum384(b)
		return hex.EncodeToString(h[:]), nil
	case "sha512":
		h := sha512.Sum512(b)
		return hex.EncodeToString(h[:]), nil
	default:
		return "", fmt.Errorf("unsupported hash algorithm: %s", algorithm)
	}
}

func ComputeLeafHash(resourceType, resourceName, content, hashMode, contentRef string) (string, error) {
	if !resourceTypePattern.MatchString(resourceType) {
		return "", fmt.Errorf("invalid resource_type %q", resourceType)
	}
	if hashMode == "" {
		hashMode = "content"
	}
	if hashMode != "content" && hashMode != "pointer" {
		return "", fmt.Errorf("unsupported hash_mode %q (expected 'content' or 'pointer')", hashMode)
	}
	hashable := content
	if hashMode == "pointer" {
		if contentRef == "" {
			return "", errors.New("content_ref is required when hash_mode='pointer'")
		}
		hashable = contentRef
	}
	return ComputeGovernanceHash(resourceType+":"+resourceName+":"+hashable, "sha256")
}

func computeMerkleRoot(sortedHashes []string) (string, error) {
	if len(sortedHashes) == 0 {
		return "", errors.New("cannot compute merkle root of empty list")
	}
	if len(sortedHashes) == 1 {
		return sortedHashes[0], nil
	}

	level := append([]string{}, sortedHashes...)
	for len(level) > 1 {
		next := make([]string, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 >= len(level) {
				next = append(next, level[i])
				continue
			}
			parent, err := ComputeGovernanceHash(level[i]+level[i+1], "sha256")
			if err != nil {
				return "", err
			}
			next = append(next, parent)
		}
		level = next
	}
	return level[0], nil
}

func ComputeMerkleGovernanceHash(resources []Resource) (string, *GovernanceMerkleTree, error) {
	return ComputeMerkleGovernanceHashWithProofs(resources, false)
}

func ComputeMerkleGovernanceHashWithProofs(resources []Resource, includeInclusionProofs bool) (string, *GovernanceMerkleTree, error) {
	if len(resources) == 0 {
		return "", nil, errors.New("at least one resource is required")
	}
	if len(resources) == 1 {
		r := resources[0]
		hashMode := r.HashMode
		if hashMode == "" {
			hashMode = "content"
		}
		if hashMode != "content" && hashMode != "pointer" {
			return "", nil, fmt.Errorf("unsupported hash_mode %q (expected 'content' or 'pointer')", hashMode)
		}
		if hashMode == "pointer" {
			if r.ContentRef == "" {
				return "", nil, errors.New("content_ref is required when hash_mode='pointer'")
			}
			flat, err := ComputeGovernanceHash(r.ContentRef, "sha256")
			return flat, nil, err
		}
		flat, err := ComputeGovernanceHash(r.Content, "sha256")
		return flat, nil, err
	}

	leaves := make([]MerkleLeaf, 0, len(resources))
	for _, r := range resources {
		hashMode := r.HashMode
		if hashMode == "" {
			hashMode = "content"
		}
		leafHash, err := ComputeLeafHash(r.ResourceType, r.ResourceName, r.Content, hashMode, r.ContentRef)
		if err != nil {
			return "", nil, err
		}
		leaf := MerkleLeaf{
			ResourceType: r.ResourceType,
			ResourceName: r.ResourceName,
			Hash:         leafHash,
		}
		if hashMode != "content" {
			leaf.HashMode = hashMode
		}
		if r.ContentRef != "" {
			leaf.ContentRef = r.ContentRef
		}
		leaves = append(leaves, leaf)
	}

	sort.Slice(leaves, func(i, j int) bool {
		return leaves[i].Hash < leaves[j].Hash
	})

	sortedHashes := make([]string, len(leaves))
	for i, l := range leaves {
		sortedHashes[i] = l.Hash
	}

	root, err := computeMerkleRoot(sortedHashes)
	if err != nil {
		return "", nil, err
	}

	tree := &GovernanceMerkleTree{
		Algorithm: "sha256",
		LeafCount: len(leaves),
		Leaves:    leaves,
	}
	if includeInclusionProofs {
		tree.InclusionProofs = BuildInclusionProofs(tree)
	}
	return root, tree, nil
}

func BuildInclusionProofs(tree *GovernanceMerkleTree) []MerkleInclusionProof {
	if tree == nil || len(tree.Leaves) == 0 {
		return []MerkleInclusionProof{}
	}

	type node struct {
		Hash        string
		LeafIndexes []int
	}

	proofPaths := make([][]MerkleProofStep, len(tree.Leaves))
	nodes := make([]node, 0, len(tree.Leaves))
	for i, leaf := range tree.Leaves {
		nodes = append(nodes, node{
			Hash:        leaf.Hash,
			LeafIndexes: []int{i},
		})
	}

	for len(nodes) > 1 {
		next := make([]node, 0, (len(nodes)+1)/2)
		for i := 0; i < len(nodes); i += 2 {
			if i+1 >= len(nodes) {
				next = append(next, nodes[i])
				continue
			}
			left := nodes[i]
			right := nodes[i+1]

			for _, leafIndex := range left.LeafIndexes {
				proofPaths[leafIndex] = append(proofPaths[leafIndex], MerkleProofStep{
					SiblingHash:     right.Hash,
					SiblingPosition: "right",
				})
			}
			for _, leafIndex := range right.LeafIndexes {
				proofPaths[leafIndex] = append(proofPaths[leafIndex], MerkleProofStep{
					SiblingHash:     left.Hash,
					SiblingPosition: "left",
				})
			}

			parentHash, _ := ComputeGovernanceHash(left.Hash+right.Hash, "sha256")
			next = append(next, node{
				Hash:        parentHash,
				LeafIndexes: append(append([]int{}, left.LeafIndexes...), right.LeafIndexes...),
			})
		}
		nodes = next
	}

	proofs := make([]MerkleInclusionProof, 0, len(tree.Leaves))
	for i, leaf := range tree.Leaves {
		proofs = append(proofs, MerkleInclusionProof{
			LeafHash:  leaf.Hash,
			ProofPath: proofPaths[i],
		})
	}
	return proofs
}

func VerifyInclusionProof(rootHash, leafHash string, proofPath []MerkleProofStep) (bool, error) {
	current := strings.TrimSpace(leafHash)
	expected := strings.TrimSpace(rootHash)
	if current == "" || expected == "" {
		return false, nil
	}

	for _, step := range proofPath {
		sibling := strings.TrimSpace(step.SiblingHash)
		position := strings.TrimSpace(step.SiblingPosition)
		if sibling == "" {
			return false, nil
		}
		switch position {
		case "left":
			current, _ = ComputeGovernanceHash(sibling+current, "sha256")
		case "right":
			current, _ = ComputeGovernanceHash(current+sibling, "sha256")
		default:
			return false, fmt.Errorf("invalid sibling_position in proof step: %q", position)
		}
	}
	return current == expected, nil
}

func CreateAIGPEvent(opts CreateEventOptions) (AIGPEvent, error) {
	eventType, err := NormalizeEventType(opts.EventType)
	if err != nil {
		return AIGPEvent{}, err
	}

	eventID, err := generateEventID()
	if err != nil {
		return AIGPEvent{}, err
	}

	traceID := strings.TrimSpace(opts.TraceID)
	if traceID == "" {
		traceID, err = randomHex(16)
		if err != nil {
			return AIGPEvent{}, err
		}
	}

	annotations := opts.Annotations
	if annotations == nil {
		annotations = map[string]any{}
	}

	hashType := opts.HashType
	if hashType == "" {
		hashType = "sha256"
	}

	specVersion := opts.SpecVersion
	if specVersion == "" {
		specVersion = "0.10.0"
	}

	sequenceNumber := opts.SequenceNumber
	if sequenceNumber <= 0 {
		sequenceNumber = nextSequenceNumber(opts.AgentID, traceID)
	}
	governanceHash := strings.TrimSpace(opts.GovernanceHash)
	if governanceHash == "" {
		return AIGPEvent{}, errors.New("governance_hash is required and cannot be empty")
	}

	event := AIGPEvent{
		EventID:              eventID,
		EventType:            eventType,
		EventCategory:        NormalizeEventCategory(opts.EventCategory),
		EventTime:            time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		AgentID:              opts.AgentID,
		GovernanceHash:       governanceHash,
		TraceID:              traceID,
		SpanID:               opts.SpanID,
		ParentSpanID:         opts.ParentSpanID,
		TraceFlags:           opts.TraceFlags,
		AgentName:            opts.AgentName,
		OrgID:                opts.OrgID,
		OrgName:              opts.OrgName,
		PolicyID:             opts.PolicyID,
		PolicyName:           opts.PolicyName,
		PolicyVersion:        opts.PolicyVersion,
		PromptID:             opts.PromptID,
		PromptName:           opts.PromptName,
		PromptVersion:        opts.PromptVersion,
		HashType:             hashType,
		DataClassification:   opts.DataClassification,
		TemplateRendered:     opts.TemplateRendered,
		DenialReason:         opts.DenialReason,
		ViolationType:        opts.ViolationType,
		Severity:             opts.Severity,
		SourceIP:             opts.SourceIP,
		RequestMethod:        opts.RequestMethod,
		RequestPath:          opts.RequestPath,
		QueryHash:            opts.QueryHash,
		PreviousHash:         opts.PreviousHash,
		Annotations:          annotations,
		EventSignature:       opts.EventSignature,
		SignatureKeyID:       opts.SignatureKeyID,
		SequenceNumber:       sequenceNumber,
		CausalityRef:         opts.CausalityRef,
		SpecVersion:          specVersion,
		GovernanceMerkleTree: opts.GovernanceMerkleTree,
	}
	return event, nil
}

func nextSequenceNumber(agentID, traceID string) int64 {
	key := strings.TrimSpace(agentID) + "|" + strings.TrimSpace(traceID)
	sequenceMu.Lock()
	defer sequenceMu.Unlock()
	sequenceCounters[key] = sequenceCounters[key] + 1
	return sequenceCounters[key]
}

// EmitAIGPEvent is a convenience helper for <30s integration flows.
// If GovernanceHash is empty, it computes it from content using HashType (default sha256),
// then creates an AIGP event.
func EmitAIGPEvent(opts CreateEventOptions, content string) (AIGPEvent, error) {
	if strings.TrimSpace(opts.GovernanceHash) == "" {
		hashType := strings.TrimSpace(opts.HashType)
		if hashType == "" {
			hashType = "sha256"
		}
		if hashType == "merkle-sha256" {
			return AIGPEvent{}, errors.New("governance_hash is required when hash_type is merkle-sha256")
		}
		if strings.TrimSpace(content) == "" {
			return AIGPEvent{}, errors.New("content is required when governance_hash is not provided")
		}
		hash, err := ComputeGovernanceHash(content, hashType)
		if err != nil {
			return AIGPEvent{}, err
		}
		opts.GovernanceHash = hash
	}
	return CreateAIGPEvent(opts)
}

func ValidateAIGPEvent(event AIGPEvent) []string {
	errs := make([]string, 0)
	if event.EventID == "" {
		errs = append(errs, "missing required field: event_id")
	}
	if event.EventType == "" {
		errs = append(errs, "missing required field: event_type")
	} else if !eventTypePattern.MatchString(event.EventType) {
		errs = append(errs, "event_type must match ^[A-Z][A-Z0-9_]*$")
	}
	if event.EventCategory == "" {
		errs = append(errs, "missing required field: event_category")
	}
	if event.EventTime == "" {
		errs = append(errs, "missing required field: event_time")
	}
	if event.AgentID == "" {
		errs = append(errs, "missing required field: agent_id")
	}
	if event.TraceID == "" {
		errs = append(errs, "missing required field: trace_id")
	} else if !isValidTraceID(event.TraceID, event.SpanID) {
		if strings.TrimSpace(event.SpanID) != "" {
			errs = append(errs, "trace_id must be 32-char lowercase hex when span_id is present")
		} else {
			errs = append(errs, "trace_id must be 32-char lowercase hex, UUID v4, or trace-/req- prefixed UUID v4")
		}
	}
	if strings.TrimSpace(event.GovernanceHash) == "" {
		errs = append(errs, "governance_hash must be a non-empty string")
	}
	if event.SequenceNumber < 1 {
		errs = append(errs, "sequence_number must be an integer >= 1")
	}
	return errs
}

func isValidTraceID(traceID, spanID string) bool {
	traceID = strings.TrimSpace(traceID)
	spanID = strings.TrimSpace(spanID)
	if spanID != "" {
		return traceIDOtelPattern.MatchString(traceID)
	}
	return traceIDOtelPattern.MatchString(traceID) ||
		traceIDUUIDV4Pattern.MatchString(traceID) ||
		traceIDPrefixedUUIDV4Pattern.MatchString(traceID)
}

func CeTypeFromEventType(eventType string) (string, error) {
	normalized, err := NormalizeEventType(eventType)
	if err != nil {
		return "", err
	}
	return AIGPTypePrefix + strings.ToLower(normalized), nil
}

func EventTypeFromCeType(ceType string) (string, error) {
	if !strings.HasPrefix(ceType, AIGPTypePrefix) {
		return "", fmt.Errorf("cloudevents type %q does not start with %q", ceType, AIGPTypePrefix)
	}
	return strings.TrimPrefix(ceType, AIGPTypePrefix), nil
}

func eventToMap(event AIGPEvent) (map[string]any, error) {
	b, err := json.Marshal(event)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func WrapAsCloudEvent(event AIGPEvent, includeDataschema bool) (map[string]any, error) {
	if event.EventID == "" || event.EventType == "" || event.AgentID == "" {
		return nil, errors.New("aigp event must have event_id, event_type, and agent_id to wrap as cloudevent")
	}

	ceType, err := CeTypeFromEventType(event.EventType)
	if err != nil {
		return nil, err
	}

	orgID := event.OrgID
	if orgID == "" {
		orgID = "default"
	}

	data, err := eventToMap(event)
	if err != nil {
		return nil, err
	}

	ce := map[string]any{
		"specversion":     CESpecVersion,
		"id":              event.EventID,
		"type":            ceType,
		"source":          AIGPSourceScheme + orgID + "/" + event.AgentID,
		"datacontenttype": "application/json",
		"aigpagentid":     event.AgentID,
		"data":            data,
	}

	if event.EventTime != "" {
		ce["time"] = event.EventTime
	}
	if includeDataschema {
		ce["dataschema"] = AIGPDataSchema
	}
	if event.PolicyName != "" {
		ce["subject"] = event.PolicyName
	} else if event.PromptName != "" {
		ce["subject"] = event.PromptName
	}
	if orgID != "default" {
		ce["aigporgid"] = orgID
	}
	if event.EventCategory != "" {
		ce["aigpcategory"] = event.EventCategory
	}
	if event.DataClassification != "" {
		ce["aigpclassification"] = event.DataClassification
	}
	if event.Severity != "" {
		ce["aigpseverity"] = event.Severity
	}
	if event.HashType != "" {
		ce["aigphashtype"] = event.HashType
	}

	return ce, nil
}

func UnwrapFromCloudEvent(ce map[string]any) (map[string]any, error) {
	specVersion, _ := ce["specversion"].(string)
	if specVersion != CESpecVersion {
		return nil, fmt.Errorf("unsupported cloudevents specversion: %q", specVersion)
	}
	ceType, _ := ce["type"].(string)
	if !strings.HasPrefix(ceType, AIGPTypePrefix) {
		return nil, fmt.Errorf("cloudevents type %q does not start with %q", ceType, AIGPTypePrefix)
	}
	data, ok := ce["data"].(map[string]any)
	if !ok {
		return nil, errors.New("cloudevents 'data' must be an object")
	}
	return data, nil
}

func BuildCEHeaders(event AIGPEvent, prefix string) (map[string]string, error) {
	if prefix == "" {
		prefix = "ce-"
	}
	ceType, err := CeTypeFromEventType(event.EventType)
	if err != nil {
		return nil, err
	}

	orgID := event.OrgID
	if orgID == "" {
		orgID = "default"
	}

	headers := map[string]string{
		prefix + "specversion": CESpecVersion,
		prefix + "id":          event.EventID,
		prefix + "type":        ceType,
		prefix + "source":      AIGPSourceScheme + orgID + "/" + event.AgentID,
		prefix + "aigpagentid": event.AgentID,
	}
	if event.EventTime != "" {
		headers[prefix+"time"] = event.EventTime
	}
	if orgID != "default" {
		headers[prefix+"aigporgid"] = orgID
	}
	if event.EventCategory != "" {
		headers[prefix+"aigpcategory"] = event.EventCategory
	}
	if event.DataClassification != "" {
		headers[prefix+"aigpclassification"] = event.DataClassification
	}
	if event.Severity != "" {
		headers[prefix+"aigpseverity"] = event.Severity
	}
	if event.HashType != "" {
		headers[prefix+"aigphashtype"] = event.HashType
	}
	return headers, nil
}

func SignEventWithSigner(event AIGPEvent, signer EventSigner) (AIGPEvent, error) {
	if signer == nil {
		return event, errors.New("signer is required")
	}

	signableMap, err := eventToMap(event)
	if err != nil {
		return event, err
	}
	delete(signableMap, "event_signature")
	delete(signableMap, "signature_key_id")

	header := map[string]any{
		"alg": signer.Algorithm(),
		"typ": "JWT",
	}
	if strings.TrimSpace(signer.KeyID()) != "" {
		header["kid"] = signer.KeyID()
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return event, err
	}
	payloadJSON, err := json.Marshal(signableMap)
	if err != nil {
		return event, err
	}

	headerB64 := base64URLEncode(headerJSON)
	payloadB64 := base64URLEncode(payloadJSON)
	signingInput := []byte(headerB64 + "." + payloadB64)

	signature, err := signer.Sign(signingInput)
	if err != nil {
		return event, err
	}

	event.EventSignature = headerB64 + "." + payloadB64 + "." + base64URLEncode(signature)
	event.SignatureKeyID = signer.KeyID()
	return event, nil
}

type RetryPolicy struct {
	MaxAttempts int
	BaseDelay   time.Duration
	MaxDelay    time.Duration
}

func (p RetryPolicy) delayForAttempt(attempt int) time.Duration {
	maxAttempts := p.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 3
	}
	baseDelay := p.BaseDelay
	if baseDelay <= 0 {
		baseDelay = 100 * time.Millisecond
	}
	maxDelay := p.MaxDelay
	if maxDelay <= 0 {
		maxDelay = 2 * time.Second
	}

	delay := baseDelay * time.Duration(1<<max(0, attempt-1))
	if delay > maxDelay {
		return maxDelay
	}
	return delay
}

type SenderFunc func(event AIGPEvent) error
type SleepFunc func(time.Duration)

type ReliableEmitter struct {
	sender      SenderFunc
	retryPolicy RetryPolicy
	idempotent  bool
	sleepFn     SleepFunc

	mu          sync.Mutex
	deliveredID map[string]struct{}
	failed      []AIGPEvent
}

func NewReliableEmitter(sender SenderFunc, retryPolicy RetryPolicy, idempotent bool, sleepFn SleepFunc) *ReliableEmitter {
	if sleepFn == nil {
		sleepFn = time.Sleep
	}
	if retryPolicy.MaxAttempts <= 0 {
		retryPolicy.MaxAttempts = 3
	}
	if retryPolicy.BaseDelay <= 0 {
		retryPolicy.BaseDelay = 100 * time.Millisecond
	}
	if retryPolicy.MaxDelay <= 0 {
		retryPolicy.MaxDelay = 2 * time.Second
	}
	return &ReliableEmitter{
		sender:      sender,
		retryPolicy: retryPolicy,
		idempotent:  idempotent,
		sleepFn:     sleepFn,
		deliveredID: map[string]struct{}{},
		failed:      []AIGPEvent{},
	}
}

func (e *ReliableEmitter) PendingCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.failed)
}

func (e *ReliableEmitter) Emit(event AIGPEvent) bool {
	eventID := strings.TrimSpace(event.EventID)
	if e.idempotent && eventID != "" {
		e.mu.Lock()
		_, seen := e.deliveredID[eventID]
		e.mu.Unlock()
		if seen {
			return true
		}
	}

	for attempt := 1; attempt <= e.retryPolicy.MaxAttempts; attempt++ {
		if err := e.sender(event); err == nil {
			if eventID != "" {
				e.mu.Lock()
				e.deliveredID[eventID] = struct{}{}
				e.mu.Unlock()
			}
			return true
		}
		if attempt < e.retryPolicy.MaxAttempts {
			e.sleepFn(e.retryPolicy.delayForAttempt(attempt))
		}
	}

	e.mu.Lock()
	e.failed = append(e.failed, event)
	e.mu.Unlock()
	return false
}

func (e *ReliableEmitter) FlushFailed(maxItems int) (delivered int, pending int) {
	if maxItems <= 0 {
		maxItems = 1000
	}

	e.mu.Lock()
	target := append([]AIGPEvent{}, e.failed...)
	e.failed = []AIGPEvent{}
	e.mu.Unlock()

	if len(target) > maxItems {
		e.mu.Lock()
		e.failed = append(e.failed, target[maxItems:]...)
		e.mu.Unlock()
		target = target[:maxItems]
	}

	for _, event := range target {
		if e.Emit(event) {
			delivered++
		}
	}

	return delivered, e.PendingCount()
}

func base64URLEncode(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

func leftPad32(data []byte) []byte {
	if len(data) >= 32 {
		return data[len(data)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(data):], data)
	return out
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
