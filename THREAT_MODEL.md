# Threat model — germline

A fake child claims descent — genesis requires the parent's signature; the child must countersign to enter the lineage. A parent claims a child it never bore — the child's countersignature over its own genesis is required. Generation arithmetic is inflated — generation must be parent+1 when the parent was born in the same lineage. A bequest is silently revoked — revocation is a signed, visible event; revoked ≠ erased. Identity confusion — the child's key is fresh; descendants prove lineage without sharing identity.

## What this crate guarantees

- A genesis enters the lineage only with both signatures verified.
- Bequests carry provenance (native / inherited) and revocability at grant time.
- Descent is hop-by-hop verifiable; a child is never the parent's identity.

## What it does not guarantee

- Protection against a verifier who never calls `verify()`.
- Integrity of inputs produced by other systems — this crate verifies
  signatures and chains over what it is given; garbage that verifies is
  still garbage.
