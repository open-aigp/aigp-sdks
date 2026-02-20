using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using AIGP.Sdk;

namespace AIGP.Sdk.SmokeTests;

internal static class Program
{
    public static int Main()
    {
        try
        {
            NormalizeEventTypeMapsAliases();
            CreateAndValidateEvent();
            EmitComputesGovernanceHash();
            EmitRequiresContentWhenHashMissing();
            ComputeMerkleHandlesSingleAndMultiResource();
            InclusionProofsRoundTripAndTamperCheck();
            HashModeValidation();
            SignerAndReliableEmitterHelpers();
            CloudEventHelpers();
            CreateRejectsEmptyGovernanceHash();
            ValidateRequiresW3CTraceWhenSpanPresent();
            ConformanceFixtures();

            Console.WriteLine(".NET smoke tests passed");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($".NET smoke tests failed: {ex.Message}");
            return 1;
        }
    }

    private static void NormalizeEventTypeMapsAliases()
    {
        var mapped = AIGP.NormalizeEventType("governance.policy.delivered");
        Expect(mapped == "INJECT_SUCCESS", $"expected INJECT_SUCCESS, got {mapped}");

        var custom = AIGP.NormalizeEventType("myplatform.audit.login");
        Expect(custom == "MYPLATFORM_AUDIT_LOGIN", $"expected MYPLATFORM_AUDIT_LOGIN, got {custom}");
    }

    private static void CreateAndValidateEvent()
    {
        var governanceHash = AIGP.ComputeGovernanceHash("policy", "sha256");
        var evt = AIGP.CreateAIGPEvent(new CreateEventOptions
        {
            EventType = "governance.policy.delivered",
            EventCategory = "Inject",
            AgentID = "agent.test",
            GovernanceHash = governanceHash,
        });

        Expect(evt.EventType == "INJECT_SUCCESS", $"unexpected normalized event type {evt.EventType}");
        Expect(evt.EventCategory == "inject", $"unexpected normalized event category {evt.EventCategory}");
        Expect(!string.IsNullOrWhiteSpace(evt.TraceID), "trace_id should be auto-generated");
        Expect(evt.SpecVersion == "0.10.0", $"unexpected default spec_version {evt.SpecVersion}");

        var errors = AIGP.ValidateAIGPEvent(evt);
        Expect(errors.Count == 0, "expected no validation errors");
    }

    private static void EmitComputesGovernanceHash()
    {
        var evt = AIGP.EmitAIGPEvent(new CreateEventOptions
        {
            EventType = "INJECT_SUCCESS",
            EventCategory = "inject",
            AgentID = "agent.test",
        }, "Max position: $10M");

        var expected = AIGP.ComputeGovernanceHash("Max position: $10M", "sha256");
        Expect(evt.GovernanceHash == expected, "expected computed governance_hash");
    }

    private static void EmitRequiresContentWhenHashMissing()
    {
        try
        {
            AIGP.EmitAIGPEvent(new CreateEventOptions
            {
                EventType = "INJECT_SUCCESS",
                EventCategory = "inject",
                AgentID = "agent.test",
            }, string.Empty);
        }
        catch (ArgumentException ex)
        {
            Expect(ex.Message.Contains("content is required when governance_hash is not provided", StringComparison.Ordinal), "unexpected error message for empty content");
            return;
        }

        throw new Exception("expected error when content and governance_hash are both missing");
    }

    private static void ComputeMerkleHandlesSingleAndMultiResource()
    {
        var (singleRoot, singleTree) = AIGP.ComputeMerkleGovernanceHash(new List<Resource>
        {
            new Resource { ResourceType = "policy", ResourceName = "policy.limits", Content = "Max $10M" },
        });

        Expect(singleTree == null, "expected null tree for single resource");
        var expectedSingle = AIGP.ComputeGovernanceHash("Max $10M", "sha256");
        Expect(singleRoot == expectedSingle, "single resource root mismatch");

        var (multiRoot, multiTree) = AIGP.ComputeMerkleGovernanceHash(new List<Resource>
        {
            new Resource { ResourceType = "policy", ResourceName = "policy.limits", Content = "Max $10M" },
            new Resource { ResourceType = "prompt", ResourceName = "prompt.system", Content = "You are a trading assistant" },
        });

        Expect(!string.IsNullOrWhiteSpace(multiRoot), "expected non-empty merkle root");
        Expect(multiTree != null && multiTree.LeafCount == 2, "expected tree with 2 leaves");
    }

    private static void HashModeValidation()
    {
        try
        {
            AIGP.ComputeLeafHash("policy", "policy.limits", "Max $10M", "bogus", string.Empty);
            throw new Exception("expected error for invalid hash_mode");
        }
        catch (ArgumentException)
        {
        }

        try
        {
            AIGP.ComputeMerkleGovernanceHash(new List<Resource>
            {
                new Resource { ResourceType = "policy", ResourceName = "policy.limits", HashMode = "pointer" },
            });
            throw new Exception("expected error when hash_mode=pointer and content_ref is missing");
        }
        catch (ArgumentException)
        {
        }
    }

    private static void InclusionProofsRoundTripAndTamperCheck()
    {
        var (root, tree) = AIGP.ComputeMerkleGovernanceHash(new List<Resource>
        {
            new Resource { ResourceType = "policy", ResourceName = "policy.limits", Content = "Max $10M" },
            new Resource { ResourceType = "prompt", ResourceName = "prompt.system", Content = "You are a trading assistant" },
            new Resource { ResourceType = "tool", ResourceName = "tool.quote", Content = "allow" },
        }, includeInclusionProofs: true);

        Expect(tree != null, "expected non-null merkle tree");
        Expect(tree.InclusionProofs != null && tree.InclusionProofs.Count == 3, "expected 3 inclusion proofs");

        var proof = tree.InclusionProofs[0];
        Expect(AIGP.VerifyInclusionProof(root, proof.LeafHash, proof.ProofPath), "expected inclusion proof to verify");
        Expect(!AIGP.VerifyInclusionProof("00" + root.Substring(2), proof.LeafHash, proof.ProofPath),
            "expected tampered root to fail verification");
    }

    private sealed class TestSigner : AIGP.IEventSigner
    {
        public string Algorithm => "TEST";
        public string KeyId => "kid-1";
        public byte[] Sign(byte[] signingInput) => System.Text.Encoding.UTF8.GetBytes("signed");
    }

    private sealed class RetrySender : AIGP.IEventSender
    {
        public int Attempts { get; private set; }

        public void Send(AIGPEvent eventData)
        {
            Attempts += 1;
            if (Attempts < 2)
            {
                throw new InvalidOperationException("retry");
            }
        }
    }

    private static void SignerAndReliableEmitterHelpers()
    {
        var evt = AIGP.CreateAIGPEvent(new CreateEventOptions
        {
            EventType = "INJECT_SUCCESS",
            EventCategory = "inject",
            AgentID = "agent.test",
            GovernanceHash = AIGP.ComputeGovernanceHash("policy", "sha256"),
        });

        var signed = AIGP.SignEventWithSigner(evt, new TestSigner());
        Expect(signed.SignatureKeyID == "kid-1", "expected signature key id");
        Expect(signed.EventSignature.StartsWith("ey", StringComparison.Ordinal), "expected compact JWS");

        var sender = new RetrySender();
        var emitter = new AIGP.ReliableEmitter(
            sender,
            new AIGP.RetryPolicy { MaxAttempts = 2, BaseDelayMs = 0, MaxDelayMs = 0 },
            idempotent: true
        );

        Expect(emitter.Emit(signed), "expected emit success");
        Expect(sender.Attempts == 2, $"expected 2 attempts, got {sender.Attempts}");
        Expect(emitter.PendingCount == 0, $"expected no pending failures, got {emitter.PendingCount}");

        Expect(emitter.Emit(signed), "expected duplicate emit success");
        Expect(sender.Attempts == 2, "expected idempotent dedupe to skip second delivery");
    }

    private static void CloudEventHelpers()
    {
        var governanceHash = AIGP.ComputeGovernanceHash("policy", "sha256");

        var evt = AIGP.CreateAIGPEvent(new CreateEventOptions
        {
            EventType = "INJECT_SUCCESS",
            EventCategory = "inject",
            AgentID = "agent.test",
            OrgID = "org.acme",
            PolicyName = "policy.limits",
            GovernanceHash = governanceHash,
        });

        var ce = AIGP.WrapAsCloudEvent(evt, includeDataschema: true);
        Expect(ce.Type == "org.aigp.v1.inject_success", $"unexpected cloud event type: {ce.Type}");
        Expect(ce.Source == "aigp://org.acme/agent.test", $"unexpected cloud event source: {ce.Source}");
        Expect(ce.Subject == "policy.limits", $"unexpected cloud event subject: {ce.Subject}");

        var headers = AIGP.BuildCEHeaders(evt, "ce-");
        Expect(headers["ce-type"] == "org.aigp.v1.inject_success", "unexpected ce-type header");
        Expect(headers["ce-aigpagentid"] == "agent.test", "unexpected ce-aigpagentid header");
    }

    private static void CreateRejectsEmptyGovernanceHash()
    {
        try
        {
            AIGP.CreateAIGPEvent(new CreateEventOptions
            {
                EventType = "AGENT_REGISTERED",
                EventCategory = "agent-lifecycle",
                AgentID = "agent.test",
                TraceID = "trace-550e8400-e29b-41d4-a716-446655440000",
                GovernanceHash = string.Empty,
            });
            throw new Exception("expected create error for empty governance_hash");
        }
        catch (ArgumentException ex)
        {
            Expect(ex.Message.Contains("governance_hash is required", StringComparison.Ordinal),
                "unexpected error message for empty governance_hash");
        }
    }

    private static void ValidateRequiresW3CTraceWhenSpanPresent()
    {
        var evt = AIGP.CreateAIGPEvent(new CreateEventOptions
        {
            EventType = "INJECT_SUCCESS",
            EventCategory = "inject",
            AgentID = "agent.test",
            GovernanceHash = "abc",
            TraceID = "trace-550e8400-e29b-41d4-a716-446655440000",
            SpanID = "00f067aa0ba902b7",
        });

        var errors = AIGP.ValidateAIGPEvent(evt);
        Expect(errors.Any(e => e.Contains("trace_id must be 32-char lowercase hex when span_id is present", StringComparison.Ordinal)),
            "expected validation error for non-W3C trace_id with span_id");
    }

    private static void ConformanceFixtures()
    {
        var fixturePath = FindFixturePath();
        var lines = File.ReadAllLines(fixturePath)
            .Select(x => x.Trim())
            .Where(x => x.Length > 0)
            .ToList();

        Expect(lines.Count > 1, "conformance fixture should have header + rows");
        var headers = lines[0].Split('\t');

        foreach (var line in lines.Skip(1))
        {
            var parts = line.Split('\t');
            Expect(parts.Length == headers.Length, $"invalid fixture row: {line}");
            var row = new Dictionary<string, string>(StringComparer.Ordinal);
            for (var i = 0; i < headers.Length; i++)
            {
                row[headers[i]] = parts[i];
            }

            var isValid = false;
            try
            {
                var evt = AIGP.CreateAIGPEvent(new CreateEventOptions
                {
                    EventType = row["event_type"],
                    EventCategory = row["event_category"],
                    AgentID = "agent.test",
                    TraceID = row["trace_id"],
                    SpanID = row["span_id"],
                    GovernanceHash = row["governance_hash"],
                    SequenceNumber = long.Parse(row["sequence_number"]),
                    CausalityRef = row["causality_ref"],
                });
                evt.SequenceNumber = long.Parse(row["sequence_number"]);
                evt.CausalityRef = row["causality_ref"];

                isValid = AIGP.ValidateAIGPEvent(evt).Count == 0;
            }
            catch (ArgumentException)
            {
                isValid = false;
            }
            var expectedValid = string.Equals(row["expect_valid"], "true", StringComparison.OrdinalIgnoreCase);
            Expect(isValid == expectedValid, $"fixture {row["case_id"]} failed: expected valid={expectedValid}, got valid={isValid}");
        }
    }

    private static string FindFixturePath()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            var candidate = Path.Combine(dir.FullName, "conformance", "validation-fixtures.tsv");
            if (File.Exists(candidate))
            {
                return candidate;
            }
            dir = dir.Parent;
        }

        throw new FileNotFoundException("Unable to locate conformance/validation-fixtures.tsv from test base directory.");
    }

    private static void Expect(bool condition, string message)
    {
        if (!condition)
        {
            throw new Exception(message);
        }
    }
}
