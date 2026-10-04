use germline::*;

fn make_genesis(parent: &Identity, child: &Identity, gen: u32) -> GenesisBlock {
    let tip = "ab".repeat(32);
    let mut g = GenesisBlock::issue(parent, child, gen, &tip, vec![]).unwrap();
    g.accept(child).unwrap();
    g
}

#[test]
fn birth_requires_dual_consent() {
    let parent = Identity::generate();
    let child = Identity::generate();
    let tip = "ab".repeat(32);
    let g = GenesisBlock::issue(&parent, &child, 1, &tip, vec![]).unwrap();
    assert!(g.pending());
    // Parent half verifies; the block is incomplete until the child signs.
    assert!(g.verify().is_err());
    let mut g = g;
    g.accept(&child).unwrap();
    g.verify().unwrap();
}

#[test]
fn child_is_not_parent() {
    let parent = Identity::generate();
    let tip = "ab".repeat(32);
    assert!(GenesisBlock::issue(&parent, &parent, 1, &tip, vec![]).is_err());
}

#[test]
fn three_generations_descend() {
    let root = Identity::generate();
    let child = Identity::generate();
    let grandchild = Identity::generate();
    let mut tree = Lineage::new();
    tree.add_genesis(&make_genesis(&root, &child, 1)).unwrap();
    tree.add_genesis(&make_genesis(&child, &grandchild, 2))
        .unwrap();
    assert!(tree.descends_from(&grandchild.public_key(), &child.public_key()));
    assert!(tree.descends_from(&grandchild.public_key(), &root.public_key()));
    assert!(!tree.descends_from(&root.public_key(), &grandchild.public_key()));
    tree.verify().unwrap();
}

#[test]
fn generation_must_follow_parent() {
    let parent = Identity::generate();
    let child = Identity::generate();
    let grandchild = Identity::generate();
    let mut tree = Lineage::new();
    tree.add_genesis(&make_genesis(&parent, &child, 1)).unwrap();
    // Grandchild claims generation 9 — rejected.
    assert!(tree
        .add_genesis(&make_genesis(&child, &grandchild, 9))
        .is_err());
}

#[test]
fn one_birth_per_organism() {
    let p1 = Identity::generate();
    let p2 = Identity::generate();
    let child = Identity::generate();
    let mut tree = Lineage::new();
    tree.add_genesis(&make_genesis(&p1, &child, 1)).unwrap();
    assert!(tree.add_genesis(&make_genesis(&p2, &child, 1)).is_err());
}

#[test]
fn revocable_bequest_lifecycle() {
    let parent = Identity::generate();
    let child = Identity::generate();
    let tip = "ab".repeat(32);
    let b = Bequest::grant("memory:diary", &"cd".repeat(32), true);
    let bid = b.id();
    let mut g = GenesisBlock::issue(&parent, &child, 1, &tip, vec![b]).unwrap();
    g.accept(&child).unwrap();
    let mut tree = Lineage::new();
    tree.add_genesis(&g).unwrap();
    assert!(tree.bequest_active(&bid));

    let r = Revocation::sign(&parent, &g, &bid, "scope no longer fits").unwrap();
    tree.add_revocation(&r).unwrap();
    assert!(!tree.bequest_active(&bid));
    assert!(tree.live_bequests(&child.public_key()).is_empty());
    tree.verify().unwrap();
}

#[test]
fn irrevocable_bequest_cannot_be_revoked() {
    let parent = Identity::generate();
    let child = Identity::generate();
    let tip = "ab".repeat(32);
    let b = Bequest::grant("memory:root", &"cd".repeat(32), false);
    let bid = b.id();
    let mut g = GenesisBlock::issue(&parent, &child, 1, &tip, vec![b]).unwrap();
    g.accept(&child).unwrap();
    assert!(Revocation::sign(&parent, &g, &bid, "try anyway").is_err());
}

#[test]
fn non_parent_cannot_revoke() {
    let parent = Identity::generate();
    let child = Identity::generate();
    let stranger = Identity::generate();
    let tip = "ab".repeat(32);
    let b = Bequest::grant("memory:diary", &"cd".repeat(32), true);
    let bid = b.id();
    let g = GenesisBlock::issue(&parent, &child, 1, &tip, vec![b]).unwrap();
    assert!(Revocation::sign(&stranger, &g, &bid, "mine now").is_err());
}

#[test]
fn forged_genesis_rejected() {
    let parent = Identity::generate();
    let child = Identity::generate();
    let mut g = make_genesis(&parent, &child, 1);
    g.generation = 77; // tamper after signing
    let mut tree = Lineage::new();
    assert!(tree.add_genesis(&g).is_err());
}

#[test]
fn inherited_provenance_tracks_origin() {
    let b = Bequest::inherited("memory:old", &"cd".repeat(32), true, "genesis-abc");
    assert_eq!(b.provenance, "inherited:genesis-abc");
}

#[test]
fn ancestry_walks_to_root() {
    let root = Identity::generate();
    let mid = Identity::generate();
    let leaf = Identity::generate();
    let mut tree = Lineage::new();
    tree.add_genesis(&make_genesis(&root, &mid, 1)).unwrap();
    tree.add_genesis(&make_genesis(&mid, &leaf, 2)).unwrap();
    let line = tree.ancestry(&leaf.public_key());
    assert_eq!(line.len(), 2);
    assert_eq!(line[1], root.public_key());
}
