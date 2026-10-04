# SPEC — germline (organism reproduction)

## Genesis block

```json
{
  "id": "sha256", "child": "pubkey", "parent": "pubkey",
  "generation": 0, "parent_tip": "parent chain head at birth",
  "bequests": [Bequest], "ts": 0,
  "parent_signature": "…", "child_signature": "…"
}
```

`GenesisBlock::issue(parent, child_identity, …)` or
`issue_for(parent, child_pubkey, …)` when the child's key lives
elsewhere — the parent signs the canonical body; `accept(child)`
countersigns the same body on the child's side. Consent is dual.

## Bequest

`{ "id", "resource", "content_hash", "provenance":
"native|inherited(<genesis id>)", "revocable": bool }` — a reference to
gifted memory, never the memory itself. Revocation is a signed event by
the genesis parent; the grant record stays visible (revoked ≠ erased).

## Lineage

`Lineage` — the family tree:

- `add_genesis` — both signatures must verify; `child != parent`;
  generation = parent_generation + 1 when the parent was born in-tree;
  one birth per organism.
- `ancestry(pk)` — hop-by-hop parent chain.
- `descends_from(desc, anc)` — provable descent.
- `verify()` — every signature + every generation edge.

## Invariants

- Self-reproduction rejected — two distinct keys required.
- A child is never the parent's identity — fresh keys only.
- Revocations can only come from the genesis parent.
