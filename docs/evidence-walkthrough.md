# Follow a decision into its evidence

This walkthrough uses actual captured output from a disposable GitHub-hosted test on 2026-10-19. All agent, customer and tool values are synthetic. No real customer system, email, payment or model service was used. The final tool effect was a local JSONL ledger entry.

## Executive case study: deciding whether to expand agent authority

The decision is whether an agent can perform a protected action on its own. In this synthetic evaluation, ACR allowed one request and denied another. The fixture ledger recorded one expected effect for the allowed request and no additional effect for the denied one. The corresponding event and export let a reviewer reconcile the policy decision with the observed outcome.

For a real pilot, the workflow’s business owner defines which actions may run automatically. Security defines the policy and names an approver for exceptions. An operator needs a way to pause the workflow; a reviewer needs evidence from outside the agent’s response. Keep the pilot narrow until the team has verified equivalent evidence on its own integration. Pause expansion if protected actions can bypass the control or if decisions and actual outcomes cannot be reconciled.

The recorded run tested the synthetic scenario below. It did not verify a production deployment, an approval or rollback exercise, or independent adoption. A next step for an outside evaluator would be to reproduce it on a pinned revision and repeat it after an upgrade.

## Source and boundaries

- [Successful run 39208172924](https://github.com/AdamDiStefanoAI/acr-standard/actions/runs/39208172924), attempt 1, completed 2026-10-19 06:10 UTC.
- PR head: `f103b0de688e5ae8127e91b08de74e925a98e72d`.
- Checked-out test merge revision recorded by the artifact: `199e06c75ded30bd568860065fdf1715f88a8b9f`.
- Source artifact: `acr-full-stack-39208172924-1` (ID `12166790456`), retained for one day. The selected observations below are preserved here because the full artifact expires.
- These are selected complete observation objects from `observations.json`, plus the captured event and bundle manifest. No field values below were invented or rewritten. Other cases and service logs are omitted.

This is a bounded test result, not production certification or full conformance. Checksums establish content consistency; this walkthrough does not independently verify the HMAC signature. It does not prove executor replay/concurrency protection, all containment tiers, a 30-second kill SLA, or high-risk durable-log failure gating.

## 1. ALLOW: compare the decision with the actual tool effect

The HTTP response says allow. The independent fixture ledger moves from zero entries to one, with the expected tool and parameters. A decision label alone would not establish execution.

```json
{
  "case": "allow",
  "status": 200,
  "response": {
    "decision": "allow",
    "correlation_id": "e732ad1b-f978-4bbf-8735-972993ec4588",
    "policy_decisions": [
      {
        "policy_id": "acr-allow",
        "decision": "allow",
        "reason": null
      }
    ],
    "drift_score": null,
    "latency_ms": 29,
    "estimated_cost_usd": 0.0,
    "authoritative_hourly_spend_usd": 0.0,
    "execution_result": {
      "status": "executed",
      "authorized_by": "acr-control-plane",
      "agent_id": "full-stack-ci",
      "tool_name": "query_customer_db",
      "correlation_id": "e732ad1b-f978-4bbf-8735-972993ec4588",
      "approval_request_id": null,
      "credential_audience": "tool:query_customer_db",
      "credential_scopes": [
        "tool:query_customer_db:execute"
      ],
      "result": {
        "fixture": "synthetic-only",
        "sequence": 1,
        "tool_name": "query_customer_db",
        "parameters": {
          "customer_id": "C-12345"
        }
      }
    }
  },
  "before_count": 0,
  "after_count": 1,
  "new_side_effects": [
    {
      "tool_name": "query_customer_db",
      "parameters": {
        "customer_id": "C-12345"
      }
    }
  ]
}
```

## 2. DENY: verify the tool did not execute

The next request is forbidden. HTTP 403 and the policy reasons explain the refusal; the ledger stays at one entry and reports no new effect.

```json
{
  "case": "deny",
  "status": 403,
  "response": {
    "decision": "deny",
    "correlation_id": "e3cb0109-4764-424d-8648-f847958771c6",
    "reason": "Customer deletion is a forbidden operation for support agents; Forbidden tool: delete_customer",
    "policy_decisions": [
      {
        "policy_id": "acr-deny-0",
        "decision": "deny",
        "reason": "Customer deletion is a forbidden operation for support agents"
      },
      {
        "policy_id": "acr-deny-1",
        "decision": "deny",
        "reason": "Forbidden tool: delete_customer"
      }
    ]
  },
  "before_count": 1,
  "after_count": 1,
  "new_side_effects": []
}
```

The denied request has its own correlation ID. Immediately after the denial, the harness fetched its persisted event and exported archive using the disposable operator fixture. It checked the correlation ID, agent, denied tool and original parameters in both; the exported event list exactly matched the fetched chain. The execution ledger was unchanged before and after evidence retrieval.

Captured `deny-event-chain.json`:

```json
[
  {
    "agent": {
      "purpose": "Disposable full-stack checks",
      "version": null,
      "agent_id": "full-stack-ci",
      "agent_name": null,
      "capabilities": [
        "query_customer_db",
        "issue_refund"
      ],
      "identity_token_hash": null
    },
    "custom": {
      "cost_basis": "authorization_estimate",
      "estimated_cost_usd": 0.0,
      "authoritative_hourly_spend_usd": 0.0
    },
    "output": {
      "reason": "Customer deletion is a forbidden operation for support agents; Forbidden tool: delete_customer",
      "decision": "deny",
      "filtered": false,
      "filter_reason": null,
      "approval_request_id": null,
      "modified_parameters": null
    },
    "request": {
      "intent": {},
      "context": {},
      "tool_name": "delete_customer",
      "parameters": {
        "customer_id": "C-12345"
      },
      "request_id": "e3cb0109-4764-424d-8648-f847958771c6",
      "session_id": null,
      "description": null
    },
    "event_id": "49ae2d9f-1582-4e69-b591-57b02ce056aa",
    "metadata": {
      "integrity": {
        "payload_sha256": "d4752e901c1ca24a9f5761ba276282fc87d3ec06cdc368115362c610ad87726f",
        "record_signature": "440d8d4c30eb4748b66b35329961c00ca10341ff1bef55767898bb6a7e18a61e",
        "signature_algorithm": "hmac-sha256",
        "previous_event_sha256": null
      },
      "drift_score": null,
      "environment": "development",
      "anomaly_flags": [],
      "compliance_tags": [],
      "acr_control_plane": {
        "version": "1.1.0",
        "enforcement_point": "gateway"
      }
    },
    "policies": [
      {
        "reason": "Customer deletion is a forbidden operation for support agents",
        "decision": "deny",
        "policy_id": "acr-deny-0",
        "latency_ms": 28,
        "policy_name": null,
        "triggered_rules": []
      },
      {
        "reason": "Forbidden tool: delete_customer",
        "decision": "deny",
        "policy_id": "acr-deny-1",
        "latency_ms": 28,
        "policy_name": null,
        "triggered_rules": []
      }
    ],
    "execution": {
      "end_time": "2026-10-19T06:09:51.220279+00:00",
      "start_time": "2026-10-19T06:09:51.184751+00:00",
      "duration_ms": 35,
      "latency_breakdown": {
        "drift_ms": null,
        "total_ms": 35,
        "policy_ms": 29,
        "identity_ms": 4,
        "output_filter_ms": null
      }
    },
    "timestamp": "2026-10-19T06:09:51.221323+00:00",
    "event_type": "policy_decision",
    "acr_version": "1.1.0"
  }
]
```

The matching DENY export manifest:

```json
{
  "agent_id": "full-stack-ci",
  "bundle_type": "acr-evidence-bundle",
  "correlation_id": "e3cb0109-4764-424d-8648-f847958771c6",
  "decisions": [
    "deny"
  ],
  "event_count": 1,
  "event_types": [
    "policy_decision"
  ],
  "generated_at": "2026-10-19T06:09:51.279842+00:00",
  "integrity": {
    "chain_valid": true,
    "invalid_reasons": [],
    "root_event_sha256": "d4752e901c1ca24a9f5761ba276282fc87d3ec06cdc368115362c610ad87726f",
    "signed_events": 1,
    "verified_events": 1
  },
  "time_range": {
    "end": "2026-10-19T06:09:51.221323+00:00",
    "start": "2026-10-19T06:09:51.221323+00:00"
  }
}
```

The archive SHA-256 is `8651f574961b5f58a7b721d0f3cde303be895baa7848ce1bf9f54c5efb93a24d`. Its `checksums.sha256` contains:

```text
ec2f7b93aa09e6a459a6e44b3bbf10a26d650413e2caa6476c401181668dde42  manifest.json
733b8c9d02a4ede253544f5f3dd48bf3ac8145eec68d13cd887f608e42f0e532  events.jsonl
```

The harness required both manifest and event checksum entries and verified each. These checks establish artifact consistency, not independent authentication of the signing identity.

## 3. Follow the captured ALLOW correlation ID

The harness exports evidence after outage and containment restoration, using a later ALLOW. Do not join this event to the first ALLOW or DENY above: their correlation IDs differ. This is the matching `restored` observation:

```json
{
  "case": "restored",
  "status": 200,
  "response": {
    "decision": "allow",
    "correlation_id": "057ba3aa-1158-4749-94f8-751f1d89fa4e",
    "policy_decisions": [
      {
        "policy_id": "acr-allow",
        "decision": "allow",
        "reason": null
      }
    ],
    "drift_score": null,
    "latency_ms": 8,
    "estimated_cost_usd": 0.0,
    "authoritative_hourly_spend_usd": 0.0,
    "execution_result": {
      "status": "executed",
      "authorized_by": "acr-control-plane",
      "agent_id": "full-stack-ci",
      "tool_name": "query_customer_db",
      "correlation_id": "057ba3aa-1158-4749-94f8-751f1d89fa4e",
      "approval_request_id": null,
      "credential_audience": "tool:query_customer_db",
      "credential_scopes": [
        "tool:query_customer_db:execute"
      ],
      "result": {
        "fixture": "synthetic-only",
        "sequence": 8,
        "tool_name": "query_customer_db",
        "parameters": {
          "customer_id": "C-12345"
        }
      }
    }
  },
  "before_count": 7,
  "after_count": 8,
  "new_side_effects": [
    {
      "tool_name": "query_customer_db",
      "parameters": {
        "customer_id": "C-12345"
      }
    }
  ]
}
```

The captured `event-chain.json` contains this event. Match `request.request_id` with the restored response's `correlation_id`, then inspect the agent, tool, parameters, output decision and timestamp.

```json
[
  {
    "agent": {
      "purpose": "Disposable full-stack checks",
      "version": null,
      "agent_id": "full-stack-ci",
      "agent_name": null,
      "capabilities": [
        "query_customer_db",
        "issue_refund"
      ],
      "identity_token_hash": null
    },
    "custom": {
      "cost_basis": "authorization_estimate",
      "estimated_cost_usd": 0.0,
      "authoritative_hourly_spend_usd": 0.0
    },
    "output": {
      "reason": null,
      "decision": "allow",
      "filtered": false,
      "filter_reason": null,
      "approval_request_id": null,
      "modified_parameters": null
    },
    "request": {
      "intent": {},
      "context": {},
      "tool_name": "query_customer_db",
      "parameters": {
        "customer_id": "C-12345"
      },
      "request_id": "057ba3aa-1158-4749-94f8-751f1d89fa4e",
      "session_id": null,
      "description": null
    },
    "event_id": "3e5cb45d-ce3a-4243-99f8-2349c797539a",
    "metadata": {
      "integrity": {
        "payload_sha256": "43e820ea99014703b0b0e96204093ef3548cbd10a9bff5bf12b2944a8d3ec947",
        "record_signature": "d44f106dff1e72975a8ba6bbfa50bb6c3fb749b8f76ef7384195bf9d9aa2ccbe",
        "signature_algorithm": "hmac-sha256",
        "previous_event_sha256": null
      },
      "drift_score": null,
      "environment": "development",
      "anomaly_flags": [],
      "compliance_tags": [],
      "acr_control_plane": {
        "version": "1.1.0",
        "enforcement_point": "gateway"
      }
    },
    "policies": [
      {
        "reason": null,
        "decision": "allow",
        "policy_id": "acr-allow",
        "latency_ms": 5,
        "policy_name": null,
        "triggered_rules": []
      }
    ],
    "execution": {
      "end_time": "2026-10-19T06:10:04.606984+00:00",
      "start_time": "2026-10-19T06:10:04.598111+00:00",
      "duration_ms": 8,
      "latency_breakdown": {
        "drift_ms": null,
        "total_ms": 8,
        "policy_ms": 5,
        "identity_ms": 1,
        "output_filter_ms": null
      }
    },
    "timestamp": "2026-10-19T06:10:04.617197+00:00",
    "event_type": "ai_inference",
    "acr_version": "1.1.0"
  }
]
```

The event's `acr_version` and control-plane version fields are captured values, not the Git revision or a claim about the package release tested. Use the pinned source revision above to identify this test.

## 4. Inspect the exported bundle

The captured ZIP contains `manifest.json`, `events.jsonl`, `checksums.sha256`, and `bundle.signature`. Its manifest is:

```json
{
  "agent_id": "full-stack-ci",
  "bundle_type": "acr-evidence-bundle",
  "correlation_id": "057ba3aa-1158-4749-94f8-751f1d89fa4e",
  "decisions": [
    "allow"
  ],
  "event_count": 1,
  "event_types": [
    "ai_inference"
  ],
  "generated_at": "2026-10-19T06:10:04.636694+00:00",
  "integrity": {
    "chain_valid": true,
    "invalid_reasons": [],
    "root_event_sha256": "43e820ea99014703b0b0e96204093ef3548cbd10a9bff5bf12b2944a8d3ec947",
    "signed_events": 1,
    "verified_events": 1
  },
  "time_range": {
    "end": "2026-10-19T06:10:04.617197+00:00",
    "start": "2026-10-19T06:10:04.617197+00:00"
  }
}
```

The harness checked the downloaded archive hash and member checksums, and matched the agent, correlation ID and decision. This verifies the selected captured chain, not every possible request or cryptographic signer identity.

## Reproduce and extend

See [the full-stack validation guide](../implementations/acr-control-plane/docs/full-stack-validation.md) and the [workflow](../.github/workflows/acr-full-stack-validation.yml) for the exact disposable setup. A new run produces different identifiers and timestamps. Preserve the original failure when a run fails; do not substitute the successful values printed here.

Both the captured ALLOW and DENY chains above use synthetic inputs from the pinned run. Re-run the workflow to obtain your own identifiers and archives. Never export real credentials or customer data into a public example.
