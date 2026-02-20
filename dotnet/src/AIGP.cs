using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace AIGP.Sdk
{
    public static class AIGP
    {
        public const string Version = "0.1.0";
        public const string CESpecVersion = "1.0";
        public const string AIGPTypePrefix = "org.aigp.v1.";
        public const string AIGPSourceScheme = "aigp://";
        public const string AIGPDataSchema = "https://open-aigp.org/schema/aigp-event.schema.json";

        private static readonly Regex ResourceTypePattern = new Regex("^[a-z][a-z0-9]*(-[a-z0-9]+)*$", RegexOptions.Compiled);
        private static readonly Regex EventTypePattern = new Regex("^[A-Z][A-Z0-9_]*$", RegexOptions.Compiled);
        private static readonly Regex TraceIDOtelPattern = new Regex("^[a-f0-9]{32}$", RegexOptions.Compiled);
        private static readonly Regex TraceIDUuidV4Pattern = new Regex("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly Regex TraceIDPrefixedUuidV4Pattern = new Regex("^(trace|req)-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly object SequenceLock = new object();
        private static readonly Dictionary<string, long> SequenceCounters = new Dictionary<string, long>();

        private static readonly Dictionary<string, string> EventTypeAliases = new Dictionary<string, string>
        {
            ["governance.policy.delivered"] = "INJECT_SUCCESS",
            ["governance.policy.denied"] = "INJECT_DENIED",
            ["governance.prompt.delivered"] = "PROMPT_USED",
            ["governance.prompt.denied"] = "PROMPT_DENIED",
            ["governance.policy.violation"] = "POLICY_VIOLATION",
            ["governance.a2a.call"] = "A2A_CALL",
            ["governance.tool.invoked"] = "TOOL_INVOKED",
            ["governance.tool.denied"] = "TOOL_DENIED",
            ["governance.boundary.unverified"] = "UNVERIFIED_BOUNDARY",
            ["governance.inference.started"] = "INFERENCE_STARTED",
            ["governance.inference.completed"] = "INFERENCE_COMPLETED",
            ["governance.inference.blocked"] = "INFERENCE_BLOCKED",
            ["governance.model.loaded"] = "MODEL_LOADED",
            ["governance.model.switched"] = "MODEL_SWITCHED",
            ["governance.memory.read"] = "MEMORY_READ",
            ["governance.memory.written"] = "MEMORY_WRITTEN",
            ["governance.proof"] = "GOVERNANCE_PROOF",
            ["governance.proof.delivered"] = "GOVERNANCE_PROOF",
        };

        public interface IEventSigner
        {
            string Algorithm { get; }
            string KeyId { get; }
            byte[] Sign(byte[] signingInput);
        }

        public interface IEventSender
        {
            void Send(AIGPEvent eventData);
        }

        public sealed class RetryPolicy
        {
            public int MaxAttempts { get; set; } = 3;
            public long BaseDelayMs { get; set; } = 100;
            public long MaxDelayMs { get; set; } = 2000;

            public long DelayForAttempt(int attempt)
            {
                var safeAttempt = Math.Max(1, attempt);
                var exponent = Math.Min(30, safeAttempt - 1);
                var delay = BaseDelayMs * (1L << exponent);
                return Math.Min(delay, MaxDelayMs);
            }
        }

        public sealed class FlushResult
        {
            public int Delivered { get; set; }
            public int Pending { get; set; }
        }

        public sealed class ReliableEmitter
        {
            private readonly IEventSender _sender;
            private readonly RetryPolicy _retryPolicy;
            private readonly bool _idempotent;
            private readonly HashSet<string> _deliveredIds = new HashSet<string>(StringComparer.Ordinal);
            private readonly List<AIGPEvent> _failedEvents = new List<AIGPEvent>();

            public ReliableEmitter(IEventSender sender, RetryPolicy retryPolicy = null, bool idempotent = true)
            {
                _sender = sender ?? throw new ArgumentNullException(nameof(sender));
                _retryPolicy = retryPolicy ?? new RetryPolicy();
                _idempotent = idempotent;
            }

            public int PendingCount
            {
                get
                {
                    lock (_failedEvents)
                    {
                        return _failedEvents.Count;
                    }
                }
            }

            public bool Emit(AIGPEvent eventData)
            {
                var eventId = (eventData?.EventID ?? string.Empty).Trim();
                lock (_failedEvents)
                {
                    if (_idempotent && eventId.Length > 0 && _deliveredIds.Contains(eventId))
                    {
                        return true;
                    }
                }

                var attempts = Math.Max(1, _retryPolicy.MaxAttempts);
                for (var attempt = 1; attempt <= attempts; attempt++)
                {
                    try
                    {
                        _sender.Send(eventData);
                        if (eventId.Length > 0)
                        {
                            lock (_failedEvents)
                            {
                                _deliveredIds.Add(eventId);
                            }
                        }
                        return true;
                    }
                    catch
                    {
                        if (attempt < attempts)
                        {
                            Thread.Sleep((int)_retryPolicy.DelayForAttempt(attempt));
                        }
                    }
                }

                lock (_failedEvents)
                {
                    _failedEvents.Add(CopyEvent(eventData));
                }
                return false;
            }

            public FlushResult FlushFailed(int maxItems = 1000)
            {
                var limit = maxItems > 0 ? maxItems : 1000;
                List<AIGPEvent> snapshot;
                lock (_failedEvents)
                {
                    snapshot = _failedEvents.ToList();
                }

                var remaining = new List<AIGPEvent>();
                var delivered = 0;
                for (var i = 0; i < snapshot.Count; i++)
                {
                    if (i >= limit)
                    {
                        remaining.Add(snapshot[i]);
                        continue;
                    }

                    if (Emit(snapshot[i]))
                    {
                        delivered += 1;
                    }
                    else
                    {
                        remaining.Add(snapshot[i]);
                    }
                }

                lock (_failedEvents)
                {
                    _failedEvents.Clear();
                    _failedEvents.AddRange(remaining);
                    return new FlushResult
                    {
                        Delivered = delivered,
                        Pending = _failedEvents.Count,
                    };
                }
            }
        }

        public static string NormalizeEventType(string eventType)
        {
            var raw = (eventType ?? string.Empty).Trim();
            if (raw.Length == 0)
            {
                throw new ArgumentException("event_type must be a non-empty string", nameof(eventType));
            }

            var mapped = EventTypeAliases.TryGetValue(raw, out var alias) ? alias : raw;
            if (EventTypePattern.IsMatch(mapped))
            {
                return mapped;
            }

            var normalized = Regex.Replace(mapped, "[^A-Za-z0-9]+", "_").Trim('_').ToUpperInvariant();
            if (normalized.Length == 0 || !EventTypePattern.IsMatch(normalized))
            {
                throw new ArgumentException($"event_type {eventType} cannot be normalized to valid UPPER_SNAKE_CASE", nameof(eventType));
            }
            return normalized;
        }

        public static string NormalizeEventCategory(string eventCategory)
        {
            var raw = (eventCategory ?? string.Empty).Trim().ToLowerInvariant();
            if (raw.Length == 0)
            {
                return "governance";
            }

            raw = raw.Replace("_", "-");
            raw = Regex.Replace(raw, "[^a-z0-9-]+", "-").Trim('-');
            return raw.Length == 0 ? "governance" : raw;
        }

        public static string ComputeGovernanceHash(string content, string algorithm = "sha256")
        {
            var material = Encoding.UTF8.GetBytes(content ?? string.Empty);
            var algo = (algorithm ?? "sha256").Trim().ToLowerInvariant();

            byte[] digest;
            switch (algo)
            {
                case "sha256":
                    using (var sha256 = SHA256.Create())
                    {
                        digest = sha256.ComputeHash(material);
                    }
                    break;
                case "sha384":
                    using (var sha384 = SHA384.Create())
                    {
                        digest = sha384.ComputeHash(material);
                    }
                    break;
                case "sha512":
                    using (var sha512 = SHA512.Create())
                    {
                        digest = sha512.ComputeHash(material);
                    }
                    break;
                default:
                    throw new ArgumentException($"unsupported hash algorithm: {algorithm}", nameof(algorithm));
            }

            return BytesToLowerHex(digest);
        }

        public static string ComputeLeafHash(string resourceType, string resourceName, string content, string hashMode = "content", string contentRef = "")
        {
            if (!ResourceTypePattern.IsMatch(resourceType ?? string.Empty))
            {
                throw new ArgumentException($"invalid resource_type {resourceType}", nameof(resourceType));
            }

            var mode = string.IsNullOrWhiteSpace(hashMode) ? "content" : hashMode;
            if (mode != "content" && mode != "pointer")
            {
                throw new ArgumentException($"unsupported hash_mode {hashMode} (expected 'content' or 'pointer')", nameof(hashMode));
            }

            var hashable = content ?? string.Empty;
            if (mode == "pointer")
            {
                if (string.IsNullOrWhiteSpace(contentRef))
                {
                    throw new ArgumentException("content_ref is required when hash_mode='pointer'", nameof(contentRef));
                }
                hashable = contentRef;
            }

            return ComputeGovernanceHash($"{resourceType}:{resourceName}:{hashable}", "sha256");
        }

        public static (string rootHash, GovernanceMerkleTree governanceMerkleTree) ComputeMerkleGovernanceHash(IList<Resource> resources)
        {
            return ComputeMerkleGovernanceHash(resources, includeInclusionProofs: false);
        }

        public static (string rootHash, GovernanceMerkleTree governanceMerkleTree) ComputeMerkleGovernanceHash(
            IList<Resource> resources,
            bool includeInclusionProofs)
        {
            if (resources == null || resources.Count == 0)
            {
                throw new ArgumentException("at least one resource is required", nameof(resources));
            }

            if (resources.Count == 1)
            {
                var single = resources[0] ?? new Resource();
                var mode = string.IsNullOrWhiteSpace(single.HashMode) ? "content" : single.HashMode;
                if (mode != "content" && mode != "pointer")
                {
                    throw new ArgumentException($"unsupported hash_mode {single.HashMode} (expected 'content' or 'pointer')", nameof(resources));
                }

                if (mode == "pointer")
                {
                    if (string.IsNullOrWhiteSpace(single.ContentRef))
                    {
                        throw new ArgumentException("content_ref is required when hash_mode='pointer'", nameof(resources));
                    }
                    return (ComputeGovernanceHash(single.ContentRef, "sha256"), null);
                }

                return (ComputeGovernanceHash(single.Content ?? string.Empty, "sha256"), null);
            }

            var leaves = new List<MerkleLeaf>(resources.Count);
            foreach (var resource in resources)
            {
                var current = resource ?? new Resource();
                var mode = string.IsNullOrWhiteSpace(current.HashMode) ? "content" : current.HashMode;
                var leafHash = ComputeLeafHash(current.ResourceType, current.ResourceName, current.Content, mode, current.ContentRef);

                var leaf = new MerkleLeaf
                {
                    ResourceType = current.ResourceType ?? string.Empty,
                    ResourceName = current.ResourceName ?? string.Empty,
                    Hash = leafHash,
                    HashMode = mode == "content" ? null : mode,
                    ContentRef = string.IsNullOrWhiteSpace(current.ContentRef) ? null : current.ContentRef,
                };
                leaves.Add(leaf);
            }

            var sortedLeaves = leaves.OrderBy(l => l.Hash, StringComparer.Ordinal).ToList();
            var sortedHashes = sortedLeaves.Select(l => l.Hash).ToList();
            var root = ComputeMerkleRoot(sortedHashes);
            var inclusionProofs = includeInclusionProofs ? BuildInclusionProofs(sortedLeaves) : null;

            return (root, new GovernanceMerkleTree
            {
                Algorithm = "sha256",
                LeafCount = sortedLeaves.Count,
                Leaves = sortedLeaves,
                InclusionProofs = inclusionProofs,
            });
        }

        public static List<MerkleInclusionProof> BuildInclusionProofs(IList<MerkleLeaf> leaves)
        {
            if (leaves == null || leaves.Count == 0)
            {
                return new List<MerkleInclusionProof>();
            }

            var proofPaths = new List<List<MerkleProofStep>>(leaves.Count);
            for (var i = 0; i < leaves.Count; i++)
            {
                proofPaths.Add(new List<MerkleProofStep>());
            }

            var nodes = new List<(string hash, List<int> leafIndexes)>(leaves.Count);
            for (var i = 0; i < leaves.Count; i++)
            {
                nodes.Add((leaves[i].Hash, new List<int> { i }));
            }

            while (nodes.Count > 1)
            {
                var next = new List<(string hash, List<int> leafIndexes)>((nodes.Count + 1) / 2);
                for (var i = 0; i < nodes.Count; i += 2)
                {
                    if (i + 1 >= nodes.Count)
                    {
                        next.Add(nodes[i]);
                        continue;
                    }

                    var left = nodes[i];
                    var right = nodes[i + 1];

                    foreach (var leafIndex in left.leafIndexes)
                    {
                        proofPaths[leafIndex].Add(new MerkleProofStep
                        {
                            SiblingHash = right.hash,
                            SiblingPosition = "right",
                        });
                    }
                    foreach (var leafIndex in right.leafIndexes)
                    {
                        proofPaths[leafIndex].Add(new MerkleProofStep
                        {
                            SiblingHash = left.hash,
                            SiblingPosition = "left",
                        });
                    }

                    var merged = new List<int>(left.leafIndexes.Count + right.leafIndexes.Count);
                    merged.AddRange(left.leafIndexes);
                    merged.AddRange(right.leafIndexes);
                    next.Add((ComputeGovernanceHash(left.hash + right.hash, "sha256"), merged));
                }
                nodes = next;
            }

            var proofs = new List<MerkleInclusionProof>(leaves.Count);
            for (var i = 0; i < leaves.Count; i++)
            {
                proofs.Add(new MerkleInclusionProof
                {
                    LeafHash = leaves[i].Hash,
                    ProofPath = proofPaths[i],
                });
            }
            return proofs;
        }

        public static bool VerifyInclusionProof(string rootHash, string leafHash, IList<MerkleProofStep> proofPath)
        {
            var current = (leafHash ?? string.Empty).Trim();
            var expected = (rootHash ?? string.Empty).Trim();
            if (current.Length == 0 || expected.Length == 0)
            {
                return false;
            }

            foreach (var step in proofPath ?? Array.Empty<MerkleProofStep>())
            {
                if (step == null || string.IsNullOrWhiteSpace(step.SiblingHash))
                {
                    return false;
                }

                if (step.SiblingPosition == "left")
                {
                    current = ComputeGovernanceHash(step.SiblingHash + current, "sha256");
                }
                else if (step.SiblingPosition == "right")
                {
                    current = ComputeGovernanceHash(current + step.SiblingHash, "sha256");
                }
                else
                {
                    throw new ArgumentException(
                        $"invalid sibling_position in proof step: {step.SiblingPosition} (expected 'left' or 'right')",
                        nameof(proofPath));
                }
            }

            return string.Equals(current, expected, StringComparison.Ordinal);
        }

        public static AIGPEvent SignEventWithSigner(AIGPEvent eventData, IEventSigner signer)
        {
            if (eventData == null)
            {
                throw new ArgumentNullException(nameof(eventData));
            }
            if (signer == null)
            {
                throw new ArgumentNullException(nameof(signer));
            }

            var header = new SortedDictionary<string, object>(StringComparer.Ordinal)
            {
                ["alg"] = string.IsNullOrWhiteSpace(signer.Algorithm) ? "ES256" : signer.Algorithm,
                ["typ"] = "JWT",
            };
            if (!string.IsNullOrWhiteSpace(signer.KeyId))
            {
                header["kid"] = signer.KeyId;
            }

            var payload = BuildEventMap(eventData);
            payload.Remove("event_signature");
            payload.Remove("signature_key_id");

            var headerB64 = Base64UrlEncode(Encoding.UTF8.GetBytes(CanonicalJson(header)));
            var payloadB64 = Base64UrlEncode(Encoding.UTF8.GetBytes(CanonicalJson(payload)));
            var signingInput = $"{headerB64}.{payloadB64}";
            var signature = signer.Sign(Encoding.ASCII.GetBytes(signingInput));
            if (signature == null || signature.Length == 0)
            {
                throw new ArgumentException("signer returned an empty signature", nameof(signer));
            }

            var signed = CopyEvent(eventData);
            signed.EventSignature = $"{signingInput}.{Base64UrlEncode(signature)}";
            signed.SignatureKeyID = signer.KeyId ?? string.Empty;
            return signed;
        }

        public static AIGPEvent CreateAIGPEvent(CreateEventOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            var eventType = NormalizeEventType(options.EventType);
            var traceId = string.IsNullOrWhiteSpace(options.TraceID) ? RandomHex(16) : options.TraceID.Trim();
            var governanceHash = (options.GovernanceHash ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(governanceHash))
            {
                throw new ArgumentException("governance_hash is required and cannot be empty", nameof(options));
            }

            return new AIGPEvent
            {
                EventID = Guid.NewGuid().ToString(),
                EventType = eventType,
                EventCategory = NormalizeEventCategory(options.EventCategory),
                EventTime = DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture),
                AgentID = options.AgentID ?? string.Empty,
                GovernanceHash = governanceHash,
                TraceID = traceId,
                SpanID = options.SpanID ?? string.Empty,
                ParentSpanID = options.ParentSpanID ?? string.Empty,
                TraceFlags = options.TraceFlags ?? string.Empty,
                AgentName = options.AgentName ?? string.Empty,
                OrgID = options.OrgID ?? string.Empty,
                OrgName = options.OrgName ?? string.Empty,
                PolicyID = options.PolicyID ?? string.Empty,
                PolicyName = options.PolicyName ?? string.Empty,
                PolicyVersion = options.PolicyVersion,
                PromptID = options.PromptID ?? string.Empty,
                PromptName = options.PromptName ?? string.Empty,
                PromptVersion = options.PromptVersion,
                HashType = string.IsNullOrWhiteSpace(options.HashType) ? "sha256" : options.HashType,
                DataClassification = options.DataClassification ?? string.Empty,
                TemplateRendered = options.TemplateRendered,
                DenialReason = options.DenialReason ?? string.Empty,
                ViolationType = options.ViolationType ?? string.Empty,
                Severity = options.Severity ?? string.Empty,
                SourceIP = options.SourceIP ?? string.Empty,
                RequestMethod = options.RequestMethod ?? string.Empty,
                RequestPath = options.RequestPath ?? string.Empty,
                QueryHash = options.QueryHash ?? string.Empty,
                PreviousHash = options.PreviousHash ?? string.Empty,
                Annotations = options.Annotations ?? new Dictionary<string, object>(),
                EventSignature = options.EventSignature ?? string.Empty,
                SignatureKeyID = options.SignatureKeyID ?? string.Empty,
                SequenceNumber = options.SequenceNumber > 0
                    ? options.SequenceNumber
                    : NextSequenceNumber(options.AgentID ?? string.Empty, traceId),
                CausalityRef = options.CausalityRef ?? string.Empty,
                SpecVersion = string.IsNullOrWhiteSpace(options.SpecVersion) ? "0.10.0" : options.SpecVersion,
                GovernanceMerkleTree = options.GovernanceMerkleTree,
            };
        }

        public static AIGPEvent EmitAIGPEvent(CreateEventOptions options, string content)
        {
            var opts = options ?? new CreateEventOptions();

            if (string.IsNullOrWhiteSpace(opts.GovernanceHash))
            {
                var hashType = string.IsNullOrWhiteSpace(opts.HashType) ? "sha256" : opts.HashType;
                if (hashType == "merkle-sha256")
                {
                    throw new ArgumentException("governance_hash is required when hash_type is merkle-sha256", nameof(options));
                }

                if (string.IsNullOrWhiteSpace(content))
                {
                    throw new ArgumentException("content is required when governance_hash is not provided", nameof(content));
                }

                opts.GovernanceHash = ComputeGovernanceHash(content, hashType);
            }

            return CreateAIGPEvent(opts);
        }

        public static List<string> ValidateAIGPEvent(AIGPEvent eventData)
        {
            var errors = new List<string>();
            if (eventData == null)
            {
                errors.Add("event is required");
                return errors;
            }

            if (string.IsNullOrWhiteSpace(eventData.EventID))
            {
                errors.Add("Missing required field: event_id");
            }
            if (string.IsNullOrWhiteSpace(eventData.EventType))
            {
                errors.Add("Missing required field: event_type");
            }
            else if (!EventTypePattern.IsMatch(eventData.EventType))
            {
                errors.Add("event_type must match ^[A-Z][A-Z0-9_]*$");
            }

            if (string.IsNullOrWhiteSpace(eventData.EventCategory))
            {
                errors.Add("Missing required field: event_category");
            }
            if (string.IsNullOrWhiteSpace(eventData.EventTime))
            {
                errors.Add("Missing required field: event_time");
            }
            if (string.IsNullOrWhiteSpace(eventData.AgentID))
            {
                errors.Add("Missing required field: agent_id");
            }
            if (string.IsNullOrWhiteSpace(eventData.TraceID))
            {
                errors.Add("Missing required field: trace_id");
            }
            else if (!IsValidTraceID(eventData.TraceID, eventData.SpanID))
            {
                if (!string.IsNullOrWhiteSpace(eventData.SpanID))
                {
                    errors.Add("trace_id must be 32-char lowercase hex when span_id is present");
                }
                else
                {
                    errors.Add("trace_id must be 32-char lowercase hex, UUID v4, or trace-/req- prefixed UUID v4");
                }
            }
            if (string.IsNullOrWhiteSpace(eventData.GovernanceHash))
            {
                errors.Add("governance_hash must be a non-empty string");
            }
            if (eventData.SequenceNumber < 1)
            {
                errors.Add("sequence_number must be an integer >= 1");
            }

            return errors;
        }

        private static long NextSequenceNumber(string agentID, string traceID)
        {
            var key = $"{(agentID ?? string.Empty).Trim()}|{(traceID ?? string.Empty).Trim()}";
            lock (SequenceLock)
            {
                var next = SequenceCounters.TryGetValue(key, out var current) ? current + 1 : 1;
                SequenceCounters[key] = next;
                return next;
            }
        }

        public static string CeTypeFromEventType(string eventType)
        {
            return AIGPTypePrefix + NormalizeEventType(eventType).ToLowerInvariant();
        }

        public static string EventTypeFromCeType(string ceType)
        {
            if (string.IsNullOrWhiteSpace(ceType) || !ceType.StartsWith(AIGPTypePrefix, StringComparison.Ordinal))
            {
                throw new ArgumentException($"CloudEvents type does not start with {AIGPTypePrefix}: {ceType}", nameof(ceType));
            }

            return ceType.Substring(AIGPTypePrefix.Length);
        }

        public static CloudEvent WrapAsCloudEvent(AIGPEvent eventData, bool includeDataschema = true)
        {
            if (eventData == null || string.IsNullOrWhiteSpace(eventData.EventID) || string.IsNullOrWhiteSpace(eventData.EventType) || string.IsNullOrWhiteSpace(eventData.AgentID))
            {
                throw new ArgumentException("AIGP event must have event_id, event_type, and agent_id to wrap as CloudEvent", nameof(eventData));
            }

            var orgId = string.IsNullOrWhiteSpace(eventData.OrgID) ? "default" : eventData.OrgID;
            return new CloudEvent
            {
                Specversion = CESpecVersion,
                Id = eventData.EventID,
                Type = CeTypeFromEventType(eventData.EventType),
                Source = AIGPSourceScheme + orgId + "/" + eventData.AgentID,
                Datacontenttype = "application/json",
                Time = string.IsNullOrWhiteSpace(eventData.EventTime) ? null : eventData.EventTime,
                Dataschema = includeDataschema ? AIGPDataSchema : null,
                Subject = !string.IsNullOrWhiteSpace(eventData.PolicyName)
                    ? eventData.PolicyName
                    : (!string.IsNullOrWhiteSpace(eventData.PromptName) ? eventData.PromptName : null),
                AigpAgentId = eventData.AgentID,
                AigpOrgId = orgId == "default" ? null : orgId,
                AigpCategory = string.IsNullOrWhiteSpace(eventData.EventCategory) ? null : eventData.EventCategory,
                AigpClassification = string.IsNullOrWhiteSpace(eventData.DataClassification) ? null : eventData.DataClassification,
                AigpSeverity = string.IsNullOrWhiteSpace(eventData.Severity) ? null : eventData.Severity,
                AigpHashType = string.IsNullOrWhiteSpace(eventData.HashType) ? null : eventData.HashType,
                Data = eventData,
            };
        }

        public static AIGPEvent UnwrapFromCloudEvent(CloudEvent cloudEvent)
        {
            if (cloudEvent == null || cloudEvent.Specversion != CESpecVersion)
            {
                throw new ArgumentException("Unsupported CloudEvents specversion", nameof(cloudEvent));
            }
            if (string.IsNullOrWhiteSpace(cloudEvent.Type) || !cloudEvent.Type.StartsWith(AIGPTypePrefix, StringComparison.Ordinal))
            {
                throw new ArgumentException($"CloudEvents type does not start with {AIGPTypePrefix}", nameof(cloudEvent));
            }
            if (cloudEvent.Data == null)
            {
                throw new ArgumentException("CloudEvents data must be present", nameof(cloudEvent));
            }

            return cloudEvent.Data;
        }

        public static Dictionary<string, string> BuildCEHeaders(AIGPEvent eventData, string prefix = "ce-")
        {
            if (eventData == null)
            {
                throw new ArgumentNullException(nameof(eventData));
            }

            var actualPrefix = string.IsNullOrWhiteSpace(prefix) ? "ce-" : prefix;
            var orgId = string.IsNullOrWhiteSpace(eventData.OrgID) ? "default" : eventData.OrgID;

            var headers = new Dictionary<string, string>
            {
                [actualPrefix + "specversion"] = CESpecVersion,
                [actualPrefix + "id"] = eventData.EventID ?? string.Empty,
                [actualPrefix + "type"] = CeTypeFromEventType(eventData.EventType),
                [actualPrefix + "source"] = AIGPSourceScheme + orgId + "/" + eventData.AgentID,
                [actualPrefix + "aigpagentid"] = eventData.AgentID ?? string.Empty,
            };

            if (!string.IsNullOrWhiteSpace(eventData.EventTime))
            {
                headers[actualPrefix + "time"] = eventData.EventTime;
            }
            if (orgId != "default")
            {
                headers[actualPrefix + "aigporgid"] = orgId;
            }
            if (!string.IsNullOrWhiteSpace(eventData.EventCategory))
            {
                headers[actualPrefix + "aigpcategory"] = eventData.EventCategory;
            }
            if (!string.IsNullOrWhiteSpace(eventData.DataClassification))
            {
                headers[actualPrefix + "aigpclassification"] = eventData.DataClassification;
            }
            if (!string.IsNullOrWhiteSpace(eventData.Severity))
            {
                headers[actualPrefix + "aigpseverity"] = eventData.Severity;
            }
            if (!string.IsNullOrWhiteSpace(eventData.HashType))
            {
                headers[actualPrefix + "aigphashtype"] = eventData.HashType;
            }

            return headers;
        }

        private static AIGPEvent CopyEvent(AIGPEvent src)
        {
            if (src == null)
            {
                return null;
            }

            return new AIGPEvent
            {
                EventID = src.EventID,
                EventType = src.EventType,
                EventCategory = src.EventCategory,
                EventTime = src.EventTime,
                AgentID = src.AgentID,
                GovernanceHash = src.GovernanceHash,
                TraceID = src.TraceID,
                SpanID = src.SpanID,
                ParentSpanID = src.ParentSpanID,
                TraceFlags = src.TraceFlags,
                AgentName = src.AgentName,
                OrgID = src.OrgID,
                OrgName = src.OrgName,
                PolicyID = src.PolicyID,
                PolicyName = src.PolicyName,
                PolicyVersion = src.PolicyVersion,
                PromptID = src.PromptID,
                PromptName = src.PromptName,
                PromptVersion = src.PromptVersion,
                HashType = src.HashType,
                DataClassification = src.DataClassification,
                TemplateRendered = src.TemplateRendered,
                DenialReason = src.DenialReason,
                ViolationType = src.ViolationType,
                Severity = src.Severity,
                SourceIP = src.SourceIP,
                RequestMethod = src.RequestMethod,
                RequestPath = src.RequestPath,
                QueryHash = src.QueryHash,
                PreviousHash = src.PreviousHash,
                Annotations = src.Annotations == null
                    ? new Dictionary<string, object>()
                    : new Dictionary<string, object>(src.Annotations, StringComparer.Ordinal),
                EventSignature = src.EventSignature,
                SignatureKeyID = src.SignatureKeyID,
                SequenceNumber = src.SequenceNumber,
                CausalityRef = src.CausalityRef,
                SpecVersion = src.SpecVersion,
                GovernanceMerkleTree = src.GovernanceMerkleTree,
            };
        }

        private static SortedDictionary<string, object> BuildEventMap(AIGPEvent eventData)
        {
            var payload = new SortedDictionary<string, object>(StringComparer.Ordinal)
            {
                ["event_id"] = eventData.EventID ?? string.Empty,
                ["event_type"] = eventData.EventType ?? string.Empty,
                ["event_category"] = eventData.EventCategory ?? string.Empty,
                ["event_time"] = eventData.EventTime ?? string.Empty,
                ["agent_id"] = eventData.AgentID ?? string.Empty,
                ["governance_hash"] = eventData.GovernanceHash ?? string.Empty,
                ["trace_id"] = eventData.TraceID ?? string.Empty,
                ["span_id"] = eventData.SpanID ?? string.Empty,
                ["parent_span_id"] = eventData.ParentSpanID ?? string.Empty,
                ["trace_flags"] = eventData.TraceFlags ?? string.Empty,
                ["agent_name"] = eventData.AgentName ?? string.Empty,
                ["org_id"] = eventData.OrgID ?? string.Empty,
                ["org_name"] = eventData.OrgName ?? string.Empty,
                ["policy_id"] = eventData.PolicyID ?? string.Empty,
                ["policy_name"] = eventData.PolicyName ?? string.Empty,
                ["policy_version"] = eventData.PolicyVersion,
                ["prompt_id"] = eventData.PromptID ?? string.Empty,
                ["prompt_name"] = eventData.PromptName ?? string.Empty,
                ["prompt_version"] = eventData.PromptVersion,
                ["hash_type"] = eventData.HashType ?? string.Empty,
                ["data_classification"] = eventData.DataClassification ?? string.Empty,
                ["template_rendered"] = eventData.TemplateRendered,
                ["denial_reason"] = eventData.DenialReason ?? string.Empty,
                ["violation_type"] = eventData.ViolationType ?? string.Empty,
                ["severity"] = eventData.Severity ?? string.Empty,
                ["source_ip"] = eventData.SourceIP ?? string.Empty,
                ["request_method"] = eventData.RequestMethod ?? string.Empty,
                ["request_path"] = eventData.RequestPath ?? string.Empty,
                ["query_hash"] = eventData.QueryHash ?? string.Empty,
                ["previous_hash"] = eventData.PreviousHash ?? string.Empty,
                ["annotations"] = eventData.Annotations ?? new Dictionary<string, object>(),
                ["sequence_number"] = eventData.SequenceNumber,
                ["causality_ref"] = eventData.CausalityRef ?? string.Empty,
                ["spec_version"] = eventData.SpecVersion ?? "0.10.0",
            };

            if (eventData.GovernanceMerkleTree != null)
            {
                payload["governance_merkle_tree"] = eventData.GovernanceMerkleTree;
            }
            return payload;
        }

        private static string Base64UrlEncode(byte[] bytes)
        {
            return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        private static string CanonicalJson(object value)
        {
            if (value == null)
            {
                return "null";
            }
            if (value is string stringValue)
            {
                return EscapeJson(stringValue);
            }
            if (value is bool)
            {
                return ((bool)value) ? "true" : "false";
            }
            if (value is byte || value is sbyte || value is short || value is ushort ||
                value is int || value is uint || value is long || value is ulong ||
                value is float || value is double || value is decimal)
            {
                return Convert.ToString(value, CultureInfo.InvariantCulture);
            }
            if (value is IDictionary<string, object> dict)
            {
                var keys = dict.Keys.OrderBy(k => k, StringComparer.Ordinal).ToList();
                return "{" + string.Join(",", keys.Select(key => $"{EscapeJson(key)}:{CanonicalJson(dict[key])}")) + "}";
            }
            if (value is IDictionary<string, string> strDict)
            {
                var keys = strDict.Keys.OrderBy(k => k, StringComparer.Ordinal).ToList();
                return "{" + string.Join(",", keys.Select(key => $"{EscapeJson(key)}:{CanonicalJson(strDict[key])}")) + "}";
            }
            if (value is IDictionary<string, int> intDict)
            {
                var keys = intDict.Keys.OrderBy(k => k, StringComparer.Ordinal).ToList();
                return "{" + string.Join(",", keys.Select(key => $"{EscapeJson(key)}:{CanonicalJson(intDict[key])}")) + "}";
            }
            if (value is System.Collections.IDictionary anyDict)
            {
                var entries = new List<KeyValuePair<string, object>>();
                foreach (System.Collections.DictionaryEntry entry in anyDict)
                {
                    entries.Add(new KeyValuePair<string, object>(Convert.ToString(entry.Key, CultureInfo.InvariantCulture), entry.Value));
                }
                entries.Sort((a, b) => string.CompareOrdinal(a.Key, b.Key));
                return "{" + string.Join(",", entries.Select(entry => $"{EscapeJson(entry.Key)}:{CanonicalJson(entry.Value)}")) + "}";
            }
            if (value is System.Collections.IEnumerable enumerable && !(value is string))
            {
                var items = new List<string>();
                foreach (var item in enumerable)
                {
                    items.Add(CanonicalJson(item));
                }
                return "[" + string.Join(",", items) + "]";
            }
            if (value is GovernanceMerkleTree tree)
            {
                var map = new SortedDictionary<string, object>(StringComparer.Ordinal)
                {
                    ["algorithm"] = tree.Algorithm ?? string.Empty,
                    ["leaf_count"] = tree.LeafCount,
                    ["leaves"] = tree.Leaves ?? new List<MerkleLeaf>(),
                };
                if (tree.InclusionProofs != null && tree.InclusionProofs.Count > 0)
                {
                    map["inclusion_proofs"] = tree.InclusionProofs;
                }
                return CanonicalJson(map);
            }
            if (value is MerkleLeaf leaf)
            {
                var map = new SortedDictionary<string, object>(StringComparer.Ordinal)
                {
                    ["resource_type"] = leaf.ResourceType ?? string.Empty,
                    ["resource_name"] = leaf.ResourceName ?? string.Empty,
                    ["hash"] = leaf.Hash ?? string.Empty,
                };
                if (!string.IsNullOrWhiteSpace(leaf.HashMode))
                {
                    map["hash_mode"] = leaf.HashMode;
                }
                if (!string.IsNullOrWhiteSpace(leaf.ContentRef))
                {
                    map["content_ref"] = leaf.ContentRef;
                }
                return CanonicalJson(map);
            }
            if (value is MerkleInclusionProof proof)
            {
                var map = new SortedDictionary<string, object>(StringComparer.Ordinal)
                {
                    ["leaf_hash"] = proof.LeafHash ?? string.Empty,
                    ["proof_path"] = proof.ProofPath ?? new List<MerkleProofStep>(),
                };
                return CanonicalJson(map);
            }
            if (value is MerkleProofStep step)
            {
                var map = new SortedDictionary<string, object>(StringComparer.Ordinal)
                {
                    ["sibling_hash"] = step.SiblingHash ?? string.Empty,
                    ["sibling_position"] = step.SiblingPosition ?? string.Empty,
                };
                return CanonicalJson(map);
            }
            return EscapeJson(Convert.ToString(value, CultureInfo.InvariantCulture));
        }

        private static string EscapeJson(string value)
        {
            var text = value ?? string.Empty;
            var builder = new StringBuilder(text.Length + 2);
            builder.Append('"');
            foreach (var ch in text)
            {
                switch (ch)
                {
                    case '"':
                        builder.Append("\\\"");
                        break;
                    case '\\':
                        builder.Append("\\\\");
                        break;
                    case '\b':
                        builder.Append("\\b");
                        break;
                    case '\f':
                        builder.Append("\\f");
                        break;
                    case '\n':
                        builder.Append("\\n");
                        break;
                    case '\r':
                        builder.Append("\\r");
                        break;
                    case '\t':
                        builder.Append("\\t");
                        break;
                    default:
                        if (ch < 0x20)
                        {
                            builder.AppendFormat(CultureInfo.InvariantCulture, "\\u{0:x4}", (int)ch);
                        }
                        else
                        {
                            builder.Append(ch);
                        }
                        break;
                }
            }
            builder.Append('"');
            return builder.ToString();
        }

        private static string ComputeMerkleRoot(IList<string> sortedHashes)
        {
            if (sortedHashes == null || sortedHashes.Count == 0)
            {
                throw new ArgumentException("cannot compute merkle root of empty list", nameof(sortedHashes));
            }

            if (sortedHashes.Count == 1)
            {
                return sortedHashes[0];
            }

            var level = new List<string>(sortedHashes);
            while (level.Count > 1)
            {
                var next = new List<string>((level.Count + 1) / 2);
                for (var i = 0; i < level.Count; i += 2)
                {
                    if (i + 1 >= level.Count)
                    {
                        next.Add(level[i]);
                    }
                    else
                    {
                        next.Add(ComputeGovernanceHash(level[i] + level[i + 1], "sha256"));
                    }
                }
                level = next;
            }

            return level[0];
        }

        private static bool IsValidTraceID(string traceId, string spanId)
        {
            var tid = (traceId ?? string.Empty).Trim();
            var sid = (spanId ?? string.Empty).Trim();

            if (sid.Length != 0)
            {
                return TraceIDOtelPattern.IsMatch(tid);
            }

            return TraceIDOtelPattern.IsMatch(tid)
                || TraceIDUuidV4Pattern.IsMatch(tid)
                || TraceIDPrefixedUuidV4Pattern.IsMatch(tid);
        }

        private static string RandomHex(int bytes)
        {
            var buffer = new byte[bytes];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(buffer);
            }
            return BytesToLowerHex(buffer);
        }

        private static string BytesToLowerHex(byte[] bytes)
        {
            var builder = new StringBuilder(bytes.Length * 2);
            foreach (var b in bytes)
            {
                builder.Append(b.ToString("x2", CultureInfo.InvariantCulture));
            }
            return builder.ToString();
        }
    }

    public sealed class Resource
    {
        public string ResourceType { get; set; } = string.Empty;
        public string ResourceName { get; set; } = string.Empty;
        public string Content { get; set; } = string.Empty;
        public string HashMode { get; set; } = "content";
        public string ContentRef { get; set; } = string.Empty;
    }

    public sealed class MerkleLeaf
    {
        public string ResourceType { get; set; } = string.Empty;

        public string ResourceName { get; set; } = string.Empty;

        public string Hash { get; set; } = string.Empty;

        public string HashMode { get; set; }

        public string ContentRef { get; set; }
    }

    public sealed class GovernanceMerkleTree
    {
        public string Algorithm { get; set; } = "sha256";

        public int LeafCount { get; set; }

        public List<MerkleLeaf> Leaves { get; set; } = new List<MerkleLeaf>();

        public List<MerkleInclusionProof> InclusionProofs { get; set; } = new List<MerkleInclusionProof>();
    }

    public sealed class MerkleProofStep
    {
        public string SiblingHash { get; set; } = string.Empty;

        public string SiblingPosition { get; set; } = string.Empty;
    }

    public sealed class MerkleInclusionProof
    {
        public string LeafHash { get; set; } = string.Empty;

        public List<MerkleProofStep> ProofPath { get; set; } = new List<MerkleProofStep>();
    }

    public sealed class CreateEventOptions
    {
        public string EventType { get; set; } = string.Empty;
        public string EventCategory { get; set; } = string.Empty;
        public string AgentID { get; set; } = string.Empty;
        public string TraceID { get; set; } = string.Empty;
        public string GovernanceHash { get; set; } = string.Empty;
        public string SpanID { get; set; } = string.Empty;
        public string ParentSpanID { get; set; } = string.Empty;
        public string TraceFlags { get; set; } = string.Empty;
        public string AgentName { get; set; } = string.Empty;
        public string OrgID { get; set; } = string.Empty;
        public string OrgName { get; set; } = string.Empty;
        public string PolicyID { get; set; } = string.Empty;
        public string PolicyName { get; set; } = string.Empty;
        public int PolicyVersion { get; set; }
        public string PromptID { get; set; } = string.Empty;
        public string PromptName { get; set; } = string.Empty;
        public int PromptVersion { get; set; }
        public string HashType { get; set; } = "sha256";
        public string DataClassification { get; set; } = string.Empty;
        public bool TemplateRendered { get; set; }
        public string DenialReason { get; set; } = string.Empty;
        public string ViolationType { get; set; } = string.Empty;
        public string Severity { get; set; } = string.Empty;
        public string SourceIP { get; set; } = string.Empty;
        public string RequestMethod { get; set; } = string.Empty;
        public string RequestPath { get; set; } = string.Empty;
        public string QueryHash { get; set; } = string.Empty;
        public string PreviousHash { get; set; } = string.Empty;
        public Dictionary<string, object> Annotations { get; set; }
        public string EventSignature { get; set; } = string.Empty;
        public string SignatureKeyID { get; set; } = string.Empty;
        public long SequenceNumber { get; set; }
        public string CausalityRef { get; set; } = string.Empty;
        public string SpecVersion { get; set; } = "0.10.0";
        public GovernanceMerkleTree GovernanceMerkleTree { get; set; }
    }

    public sealed class AIGPEvent
    {
        public string EventID { get; set; } = string.Empty;

        public string EventType { get; set; } = string.Empty;

        public string EventCategory { get; set; } = string.Empty;

        public string EventTime { get; set; } = string.Empty;

        public string AgentID { get; set; } = string.Empty;

        public string GovernanceHash { get; set; } = string.Empty;

        public string TraceID { get; set; } = string.Empty;

        public string SpanID { get; set; } = string.Empty;

        public string ParentSpanID { get; set; } = string.Empty;

        public string TraceFlags { get; set; } = string.Empty;

        public string AgentName { get; set; } = string.Empty;

        public string OrgID { get; set; } = string.Empty;

        public string OrgName { get; set; } = string.Empty;

        public string PolicyID { get; set; } = string.Empty;

        public string PolicyName { get; set; } = string.Empty;

        public int PolicyVersion { get; set; }

        public string PromptID { get; set; } = string.Empty;

        public string PromptName { get; set; } = string.Empty;

        public int PromptVersion { get; set; }

        public string HashType { get; set; } = "sha256";

        public string DataClassification { get; set; } = string.Empty;

        public bool TemplateRendered { get; set; }

        public string DenialReason { get; set; } = string.Empty;

        public string ViolationType { get; set; } = string.Empty;

        public string Severity { get; set; } = string.Empty;

        public string SourceIP { get; set; } = string.Empty;

        public string RequestMethod { get; set; } = string.Empty;

        public string RequestPath { get; set; } = string.Empty;

        public string QueryHash { get; set; } = string.Empty;

        public string PreviousHash { get; set; } = string.Empty;

        public Dictionary<string, object> Annotations { get; set; } = new Dictionary<string, object>();

        public string EventSignature { get; set; } = string.Empty;

        public string SignatureKeyID { get; set; } = string.Empty;

        public long SequenceNumber { get; set; }

        public string CausalityRef { get; set; } = string.Empty;

        public string SpecVersion { get; set; } = "0.10.0";

        public GovernanceMerkleTree GovernanceMerkleTree { get; set; }
    }

    public sealed class CloudEvent
    {
        public string Specversion { get; set; } = AIGP.CESpecVersion;

        public string Id { get; set; } = string.Empty;

        public string Type { get; set; } = string.Empty;

        public string Source { get; set; } = string.Empty;

        public string Datacontenttype { get; set; } = "application/json";

        public string Time { get; set; }

        public string Dataschema { get; set; }

        public string Subject { get; set; }

        public string AigpAgentId { get; set; } = string.Empty;

        public string AigpOrgId { get; set; }

        public string AigpCategory { get; set; }

        public string AigpClassification { get; set; }

        public string AigpSeverity { get; set; }

        public string AigpHashType { get; set; }

        public AIGPEvent Data { get; set; }
    }
}
