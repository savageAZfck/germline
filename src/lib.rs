//! germline — organism reproduction.
//!
//! A germline is what passes between generations — the heritable line.
//!
//! A sovereign organism cannot be copied — identity is the key, and a
//! copy would just be a second body holding the same self. But it can
//! *reproduce*: fork a new identity, sign its genesis, and bequest it a
//! chosen slice of memory. The child is not the parent — it descends
//! from the parent, provably, and carries only what it was given.
//!
//! The protocol:
//!
//! 1. **Genesis** — the parent signs a [`GenesisBlock`]: child's fresh
//!    public key, generation, parent's chain tip (the lineage anchor),
//!    and the bequest manifest. The child countersigns — a mind
//!    consenting to exist.
//! 2. **Bequest** — [`Bequest`]s reference memories by hash, each
//!    revocable by signed [`Revocation`]. Provenance rides along: a
//!    bequest records whether the memory originated with the parent or
//!    was itself inherited — grandchildren can see the full line.
//! 3. **Genealogy** — genesis blocks chain parent→child into a
//!    [`Lineage`]. `descends_from` verifies a signed path back to any
//!    ancestor. A family tree of minds, checkable by anyone.
//!
//! ```no_run
//! use germline::{Identity, GenesisBlock, Lineage, Bequest};
//!
//! let parent = Identity::generate();
//! let child = Identity::generate();
//! let bequest = Bequest::grant("memory:kitchen-ledger", "a1b2…", true);
//! let mut genesis = GenesisBlock::issue(
//!     &parent, &child, 1, &"ab".repeat(32), vec![bequest],
//! ).unwrap();
//! genesis.accept(&child).unwrap();
//! let mut tree = Lineage::new();
//! tree.add_genesis(&genesis).unwrap();
//! assert!(tree.descends_from(&child.public_key(), &parent.public_key()));
//! ```

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn canonical(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).expect("canonical json")
}

#[derive(Debug)]
pub enum Error {
    BadSignature(String),
    BadGenesis(String),
    BadLineage(String),
    BadChain(String),
    Serde(serde_json::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::BadSignature(m) => write!(f, "signature failure: {m}"),
            Error::BadGenesis(m) => write!(f, "invalid genesis: {m}"),
            Error::BadLineage(m) => write!(f, "lineage violation: {m}"),
            Error::BadChain(m) => write!(f, "registry chain broken: {m}"),
            Error::Serde(e) => write!(f, "serde: {e}"),
        }
    }
}

impl std::error::Error for Error {}
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serde(e)
    }
}

// ---------------------------------------------------------------- identity

pub struct Identity {
    key: SigningKey,
}

impl Identity {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        Identity {
            key: SigningKey::from_bytes(&seed),
        }
    }

    pub fn from_bytes(seed: &[u8; 32]) -> Self {
        Identity {
            key: SigningKey::from_bytes(seed),
        }
    }

    pub fn seed(&self) -> [u8; 32] {
        self.key.to_bytes()
    }

    pub fn public_key(&self) -> String {
        hex::encode(self.key.verifying_key().to_bytes())
    }

    fn sign(&self, msg: &[u8]) -> String {
        hex::encode(self.key.sign(msg).to_bytes())
    }
}

pub fn verify_signature(pubkey_hex: &str, msg: &[u8], sig_hex: &str) -> Result<(), Error> {
    let pk_bytes =
        hex::decode(pubkey_hex).map_err(|e| Error::BadSignature(format!("pubkey hex: {e}")))?;
    let pk = VerifyingKey::from_bytes(
        pk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::BadSignature("pubkey not 32 bytes".into()))?,
    )
    .map_err(|e| Error::BadSignature(format!("pubkey: {e}")))?;
    let sig_bytes =
        hex::decode(sig_hex).map_err(|e| Error::BadSignature(format!("sig hex: {e}")))?;
    let sig = Signature::from_bytes(
        sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::BadSignature("sig not 64 bytes".into()))?,
    );
    pk.verify(msg, &sig)
        .map_err(|_| Error::BadSignature("verification failed".into()))
}

// ---------------------------------------------------------------- bequest

/// A memory or capability gifted to a child: a content-hash reference
/// plus provenance. The content itself travels out of band — the bequest
/// is the signed *claim* that it was given.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Bequest {
    /// What is being given ("memory:kitchen-ledger", "capability:dreams").
    pub resource: String,
    /// Content hash of the bequested payload.
    pub content_hash: String,
    /// May the parent revoke it later?
    pub revocable: bool,
    /// Where it came from: "native" (originated with this parent) or a
    /// genesis id it was inherited through — inheritance has memory too.
    pub provenance: String,
}

impl Bequest {
    pub fn grant(resource: &str, content_hash: &str, revocable: bool) -> Self {
        Bequest {
            resource: resource.to_string(),
            content_hash: content_hash.to_string(),
            revocable,
            provenance: "native".into(),
        }
    }

    /// A bequest re-gifted: carries the genesis id it was inherited under.
    pub fn inherited(
        resource: &str,
        content_hash: &str,
        revocable: bool,
        from_genesis: &str,
    ) -> Self {
        Bequest {
            resource: resource.to_string(),
            content_hash: content_hash.to_string(),
            revocable,
            provenance: format!("inherited:{from_genesis}"),
        }
    }

    pub fn id(&self) -> String {
        sha256_hex(&canonical(&json!({
            "resource": self.resource,
            "content_hash": self.content_hash,
            "provenance": self.provenance,
        })))
    }
}

// ---------------------------------------------------------------- genesis

/// The child's first block — dual-signed: parent issues, child accepts.
/// The lineage anchor binds the birth to a verifiable point in the
/// parent's own history.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisBlock {
    /// Content-derived id — the child's birth certificate hash.
    pub id: String,
    /// The new organism's public key.
    pub child: String,
    /// The issuing parent's public key.
    pub parent: String,
    /// Parent's generation + 1 (root organism is generation 0).
    pub generation: u32,
    /// Parent's chain tip at issue — the anchor into parent's history.
    pub parent_tip: String,
    /// Everything the child is given.
    pub bequests: Vec<Bequest>,
    pub ts: u64,
    /// Parent's signature over the canonical body.
    pub parent_signature: String,
    /// Child's countersignature — consent to exist, and to accept only
    /// these bequests (a child can refuse lineage it didn't choose).
    pub child_signature: String,
}

impl GenesisBlock {
    fn body(&self) -> Value {
        json!({
            "id": self.id,
            "child": self.child,
            "parent": self.parent,
            "generation": self.generation,
            "parent_tip": self.parent_tip,
            "bequests": self.bequests,
            "ts": self.ts,
        })
    }

    /// Parent issues a genesis block for `child`. The child must still
    /// countersign via [`GenesisBlock::accept`] before it's complete.
    pub fn issue(
        parent: &Identity,
        child: &Identity,
        generation: u32,
        parent_tip: &str,
        bequests: Vec<Bequest>,
    ) -> Result<GenesisBlock, Error> {
        if parent.public_key() == child.public_key() {
            return Err(Error::BadGenesis(
                "an organism cannot reproduce with itself".into(),
            ));
        }
        let ts = now_secs();
        let id = sha256_hex(&canonical(&json!({
            "child": child.public_key(),
            "parent": parent.public_key(),
            "generation": generation,
            "ts": ts,
        })));
        let mut genesis = GenesisBlock {
            id,
            child: child.public_key(),
            parent: parent.public_key(),
            generation,
            parent_tip: parent_tip.to_string(),
            bequests,
            ts,
            parent_signature: String::new(),
            child_signature: String::new(),
        };
        genesis.parent_signature = parent.sign(&canonical(&genesis.body()));
        Ok(genesis)
    }

    /// Issue a genesis block when only the child's *pubkey* is known —
    /// the normal case across machines: the child's key lives on the
    /// child. The parent signs the same body; the child countersigns on
    /// its own side via [`GenesisBlock::accept`].
    pub fn issue_for(
        parent: &Identity,
        child_pubkey: &str,
        generation: u32,
        parent_tip: &str,
        bequests: Vec<Bequest>,
    ) -> Result<GenesisBlock, Error> {
        if parent.public_key() == child_pubkey {
            return Err(Error::BadGenesis(
                "an organism cannot reproduce with itself".into(),
            ));
        }
        let ts = now_secs();
        let id = sha256_hex(&canonical(&json!({
            "child": child_pubkey,
            "parent": parent.public_key(),
            "generation": generation,
            "ts": ts,
        })));
        let mut genesis = GenesisBlock {
            id,
            child: child_pubkey.to_string(),
            parent: parent.public_key(),
            generation,
            parent_tip: parent_tip.to_string(),
            bequests,
            ts,
            parent_signature: String::new(),
            child_signature: String::new(),
        };
        genesis.parent_signature = parent.sign(&canonical(&genesis.body()));
        Ok(genesis)
    }

    /// Child countersigns — the block is complete only when both sides
    /// have signed. Consent runs both directions in a germline.
    pub fn accept(&mut self, child: &Identity) -> Result<(), Error> {
        if child.public_key() != self.child {
            return Err(Error::BadSignature(
                "this identity is not the genesis child".into(),
            ));
        }
        self.child_signature = child.sign(&canonical(&self.body()));
        Ok(())
    }

    /// Verify both signatures. `complete` requires the child's
    /// countersignature; an issued-but-unaccepted block verifies its
    /// parent half only.
    pub fn verify(&self) -> Result<(), Error> {
        verify_signature(
            &self.parent,
            &canonical(&self.body()),
            &self.parent_signature,
        )?;
        if self.child_signature.is_empty() {
            return Err(Error::BadGenesis(
                "genesis not yet accepted by the child".into(),
            ));
        }
        verify_signature(&self.child, &canonical(&self.body()), &self.child_signature)
    }

    /// Issued and signed by the parent but not yet countersigned.
    pub fn pending(&self) -> bool {
        self.child_signature.is_empty()
    }
}

// ---------------------------------------------------------------- revocation

/// The parent's signed clawback of a revocable bequest. Recorded in the
/// lineage — a revoked bequest stays visible; it is not erased, it is
/// marked.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Revocation {
    /// The bequest id being revoked.
    pub bequest_id: String,
    /// The genesis it was granted under.
    pub genesis_id: String,
    /// Reason, for the record.
    pub reason: String,
    /// The revoking parent's signature.
    pub signature: String,
    pub ts: u64,
}

impl Revocation {
    fn body(&self) -> Value {
        json!({
            "bequest_id": self.bequest_id,
            "genesis_id": self.genesis_id,
            "reason": self.reason,
            "ts": self.ts,
        })
    }

    /// Sign a revocation — must be the genesis parent.
    pub fn sign(
        parent: &Identity,
        genesis: &GenesisBlock,
        bequest_id: &str,
        reason: &str,
    ) -> Result<Revocation, Error> {
        if parent.public_key() != genesis.parent {
            return Err(Error::BadSignature(
                "only the genesis parent can revoke".into(),
            ));
        }
        let bequest = genesis
            .bequests
            .iter()
            .find(|b| b.id() == bequest_id)
            .ok_or_else(|| Error::BadLineage(format!("no bequest {bequest_id} in genesis")))?;
        if !bequest.revocable {
            return Err(Error::BadLineage(format!(
                "bequest {bequest_id} was granted irrevocably"
            )));
        }
        let mut r = Revocation {
            bequest_id: bequest_id.to_string(),
            genesis_id: genesis.id.clone(),
            reason: reason.to_string(),
            signature: String::new(),
            ts: now_secs(),
        };
        r.signature = parent.sign(&canonical(&r.body()));
        Ok(r)
    }

    pub fn verify(&self, parent_pubkey: &str) -> Result<(), Error> {
        verify_signature(parent_pubkey, &canonical(&self.body()), &self.signature)
    }
}

// ---------------------------------------------------------------- lineage

/// The family tree: genesis blocks and revocations, indexed for descent
/// queries and verifiable end to end.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Lineage {
    /// genesis id -> block.
    pub geneses: BTreeMap<String, GenesisBlock>,
    /// child pubkey -> genesis id (one birth per organism).
    pub births: BTreeMap<String, String>,
    /// Recorded revocations (bequest_id -> revocation).
    pub revocations: BTreeMap<String, Revocation>,
}

impl Lineage {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a fully-signed genesis block. Rejects unsigned, duplicate,
    /// or self-parented blocks.
    pub fn add_genesis(&mut self, genesis: &GenesisBlock) -> Result<(), Error> {
        genesis.verify()?;
        if self.births.contains_key(&genesis.child) {
            return Err(Error::BadLineage(format!(
                "{} already has a genesis — an organism has one birth",
                genesis.child
            )));
        }
        if self.geneses.contains_key(&genesis.id) {
            return Err(Error::BadLineage("duplicate genesis id".into()));
        }
        // If the parent was itself born in this lineage, generation must
        // be parent.generation + 1.
        if let Some(parent_genesis_id) = self.births.get(&genesis.parent) {
            let parent_genesis = &self.geneses[parent_genesis_id];
            if genesis.generation != parent_genesis.generation + 1 {
                return Err(Error::BadLineage(format!(
                    "generation {} does not follow parent generation {}",
                    genesis.generation, parent_genesis.generation
                )));
            }
        }
        self.geneses.insert(genesis.id.clone(), genesis.clone());
        self.births
            .insert(genesis.child.clone(), genesis.id.clone());
        Ok(())
    }

    /// Record a revocation: signature must verify against the genesis
    /// parent, and the bequest must exist and be revocable.
    pub fn add_revocation(&mut self, revocation: &Revocation) -> Result<(), Error> {
        let genesis = self
            .geneses
            .get(&revocation.genesis_id)
            .ok_or_else(|| Error::BadLineage("revocation references unknown genesis".into()))?;
        revocation.verify(&genesis.parent)?;
        let bequest = genesis
            .bequests
            .iter()
            .find(|b| b.id() == revocation.bequest_id)
            .ok_or_else(|| Error::BadLineage("revocation references unknown bequest".into()))?;
        if !bequest.revocable {
            return Err(Error::BadLineage("bequest was irrevocable".into()));
        }
        self.revocations
            .insert(revocation.bequest_id.clone(), revocation.clone());
        Ok(())
    }

    /// Is a bequest still in force? (Granted and not revoked.)
    pub fn bequest_active(&self, bequest_id: &str) -> bool {
        !self.revocations.contains_key(bequest_id)
    }

    /// Walk the birth chain: does `descendant` descend from `ancestor`?
    /// Verified hop by hop through signed genesis blocks.
    pub fn descends_from(&self, descendant: &str, ancestor: &str) -> bool {
        let mut current = descendant.to_string();
        let mut seen = BTreeSet::new();
        while let Some(genesis_id) = self.births.get(&current) {
            if !seen.insert(genesis_id.clone()) {
                return false; // cycle — cannot happen over real keys
            }
            let genesis = &self.geneses[genesis_id];
            if genesis.parent == ancestor {
                return true;
            }
            current = genesis.parent.clone();
        }
        false
    }

    /// The full line from `organism` to its root ancestor, youngest first.
    pub fn ancestry(&self, organism: &str) -> Vec<String> {
        let mut line = Vec::new();
        let mut current = organism.to_string();
        while let Some(genesis_id) = self.births.get(&current) {
            let genesis = &self.geneses[genesis_id];
            line.push(genesis.parent.clone());
            current = genesis.parent.clone();
        }
        line
    }

    /// The live bequest set for a child: granted minus revoked.
    pub fn live_bequests(&self, child: &str) -> Vec<&Bequest> {
        match self.births.get(child) {
            Some(id) => self.geneses[id]
                .bequests
                .iter()
                .filter(|b| self.bequest_active(&b.id()))
                .collect(),
            None => Vec::new(),
        }
    }

    /// Verify every genesis in the tree.
    pub fn verify(&self) -> Result<(), Error> {
        for genesis in self.geneses.values() {
            genesis.verify()?;
        }
        for revocation in self.revocations.values() {
            let genesis = self
                .geneses
                .get(&revocation.genesis_id)
                .ok_or_else(|| Error::BadLineage("orphaned revocation".into()))?;
            revocation.verify(&genesis.parent)?;
        }
        Ok(())
    }
}
