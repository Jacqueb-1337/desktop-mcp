# Desktop MCP gateway authorization preflight

This milestone adds a fail-closed, host-specific policy validator. It is a prerequisite for secure routing, **not remote execution**.

## Implemented

- Versioned policy with exact 32-character host identity fingerprints and the `default` workspace.
- Explicit tool allowlisting, presently restricted to `fs_read` and `git_status`.
- Rejects unknown operations, invalid or duplicate scopes, malformed request IDs, and requests targeting a different host.
- A matching policy yields `requires_local_approval`, never `allowed` or an execution grant.
- The policy-check command does not contact an agent, read remote files, or run MCP tools.

## Local preflight

Create `host-policy.json`:

```json
{
  "version": 1,
  "hosts": [
    {"host_id": "aabbccddeeff00112233445566778899", "workspace_id": "default", "tools": ["fs_read"]}
  ]
}
```

Create `intent.json`:

```json
{
  "request_id": "05e5a337-7953-4699-820f-f6c71f0f5554",
  "target_host_id": "aabbccddeeff00112233445566778899",
  "workspace_id": "default",
  "tool": "fs_read"
}
```

Then run:

```bash
desktop-mcp-gateway --policy host-policy.json --check-intent intent.json --target-host aabbccddeeff00112233445566778899
```

The response reports `requires_local_approval` with `executed: false` and `authorization_granted: false`. Supply a different target host to receive `denied`.

## Verification

Five gateway Rust tests pass. The optimized Linux gateway was rebuilt on the NAS HDD and its preflight command was tested for both matching and mismatched hosts.

## In-memory request deduplication prerequisite

The policy module now includes a bounded, expiring `RequestLedger` for future live routing.
It checks an intent against an authenticated session host supplied by its caller and
rejects reuse of a request ID within the active retention window. Capacity exhaustion
also fails closed, and a successful preflight still only requires local approval.
Tests cover duplicates, mismatched hosts, capacity, and expiration.

**The ledger is wired into the offline `--check-intents` preflight only.**
The live TLS gateway and agent do not use it yet. The ledger is cleared on
process restart and is not durable replay protection. Never treat an offline
preflight response as authorization to execute remote operations.

Windows testing is now unblocked: Rust 1.90.0 and the locked dependencies
were installed. The gateway test suite passed 10 tests after batch integration.
## Offline batch preflight

To validate a JSON array of intent objects in one invocation:

```sh
desktop-mcp-gateway --policy host-policy.json --check-intents intent-batch.json --target-host aabbccddeeff00112233445566778899
```

Each element in `intent-batch.json` must have the same four fields as the
single `intent.json` example above. The command rejects lists larger than
128 entries and marks repeated UUIDs, unauthorized hosts/tools, and malformed
entries as denied. The output is a JSON array with `executed: false` and
`authorization_granted: false` for **every** entry. Only a policy match is
reported as `requires_local_approval`.

This CLI remains an **offline, operator-supplied identity check**. Its
`--target-host` argument is not proof of an authenticated remote session.
It does not contact the PC, grant approval, or execute any MCP operation.
## Not yet implemented

The preflight command assumes the target identity supplied by its local operator. A real gateway must derive target identity from the **authenticated TLS session**, not from untrusted input. Live request routing, target-side one-time approval, anti-replay tracking, persistent audit logs, rate limits, and an authenticated ChatGPT-facing MCP entrypoint remain disabled or unimplemented.

**Never treat a preflight result as permission to execute remote operations.**
