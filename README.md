# germline

**Organism reproduction — a sovereign mind forks a child with a signed genesis block, bequested memories, and a checkable genealogy.**

A germline is what passes between generations — the heritable line.

## Why this exists

A sovereign organism can't be *copied* — identity is the key, a copy is just a second body with the same self. But it can **reproduce**: fork a fresh identity, sign its genesis, bequest it a chosen slice of memory. The child isn't the parent — it *descends* from the parent, provably, and carries only what it was given.

## The protocol

- **`GenesisBlock`** — dual-signed birth certificate: parent issues (child key, generation, parent's chain tip as the lineage anchor, bequest manifest), **child countersigns**. Consent runs both directions — a mind accepts its own birth and can refuse lineage it didn't choose.
- **`Bequest`** — content-hash references to gifted memories/capabilities with provenance: "native" or "inherited from genesis X," so grandchildren see the full line. Each is revocable or irrevocable at grant time.
- **`Revocation`** — signed clawback by the genesis parent only; the record stays visible, the grant doesn't. Revoked ≠ erased.
- **`Lineage`** — the family tree: `descends_from(child, ancestor)` verifies hop by hop through signed blocks; generation arithmetic is enforced; one birth per organism, forever.

## Invariants

- Self-reproduction rejected — a genesis needs two distinct keys.
- Unsigned genesis can't enter the tree; forged fields break the signatures.
- Generation must be parent+1 when the parent was born in the same lineage.

## Try it

```bash
cargo run --example germline
cargo test
```

## Pair with

- `nagi` — escrow for the bequest payloads
- `wolakota` — the parent-child treaty that scopes the relationship after birth
- `manitou` — provenance spans so descendants can attest which line produced what
