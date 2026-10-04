//! Three generations: a root organism births a child, who births a
//! grandchild — signed, bequested, provable.
use germline::*;

fn main() {
    let root = Identity::generate();
    let child = Identity::generate();
    let grandchild = Identity::generate();
    let mut tree = Lineage::new();
    let tip = "ab".repeat(32);

    // Generation 1: root bequests two memories, one revocable.
    let diary = Bequest::grant("memory:diary-2019", &"cd".repeat(32), true);
    let craft = Bequest::grant("capability:dreaming", &"ef".repeat(32), false);
    let mut g1 = GenesisBlock::issue(&root, &child, 1, &tip, vec![diary.clone(), craft]).unwrap();
    g1.accept(&child).unwrap();
    tree.add_genesis(&g1).unwrap();
    println!("generation 1 born: {}…", &child.public_key()[..12]);

    // Generation 2: child passes the diary on — provenance rides along.
    let inherited = Bequest::inherited("memory:diary-2019", &"cd".repeat(32), true, &g1.id);
    let mut g2 = GenesisBlock::issue(&child, &grandchild, 2, &tip, vec![inherited]).unwrap();
    g2.accept(&grandchild).unwrap();
    tree.add_genesis(&g2).unwrap();
    println!("generation 2 born: {}…", &grandchild.public_key()[..12]);

    // Descent is provable.
    println!(
        "\ngrandchild descends from root: {}",
        tree.descends_from(&grandchild.public_key(), &root.public_key())
    );
    let line = tree.ancestry(&grandchild.public_key());
    println!("ancestry: {} hops to root", line.len());

    // The parent revokes the diary — the record stays, the grant doesn't.
    let r = Revocation::sign(&root, &g1, &diary.id(), "outgrown scope").unwrap();
    tree.add_revocation(&r).unwrap();
    println!(
        "\nchild's live bequests after revocation: {}",
        tree.live_bequests(&child.public_key()).len()
    );

    tree.verify().expect("genealogy verifies");
    println!(
        "genealogy: {} generations on record, verified",
        tree.geneses.len()
    );
}
