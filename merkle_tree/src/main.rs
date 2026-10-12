use sha2::{Sha256, Digest};

// Hash a single string using SHA-256.
// Keeping this as a standalone function makes it easy to reuse all over the place.
fn sha256(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    format!("{:x}", hasher.finalize())
}

// Combine two child hashes into a parent hash.
// Standard Merkle approach: just concatenate left + right and hash together.
fn combine(left: &str, right: &str) -> String {
    sha256(&format!("{}{}", left, right))
}

// Build a Merkle tree from a flat list of transactions and return the root hash.
// We work bottom-up: start with leaf hashes, then keep pairing them until one remains.
// If a level has an odd number of nodes, the last one is duplicated -- this is the
// standard way to handle it and keeps the tree balanced.
fn build_merkle_root(transactions: &Vec<&str>) -> String {
    if transactions.is_empty() {
        return String::from("empty");
    }

    // Step 1 -- hash every transaction to get the leaf layer
    let mut current_level: Vec<String> = transactions
        .iter()
        .map(|tx| sha256(tx))
        .collect();

    println!("Leaf hashes (one per transaction):");
    for (i, h) in current_level.iter().enumerate() {
        println!("  TX{}: {}...", i + 1, &h[..20]);
    }
    println!();

    // Step 2 -- keep merging pairs until we get a single root
    while current_level.len() > 1 {
        let mut next_level: Vec<String> = Vec::new();

        let mut i = 0;
        while i < current_level.len() {
            let left = &current_level[i];
            // If there's no right sibling, pair the node with itself
            let right = if i + 1 < current_level.len() {
                &current_level[i + 1]
            } else {
                &current_level[i]  // duplicate the last node
            };
            next_level.push(combine(left, right));
            i += 2;
        }

        current_level = next_level;
    }

    // Whatever's left is the Merkle Root
    current_level.remove(0)
}

fn main() {
    // Our four sample blockchain transactions
    let mut transactions: Vec<&str> = vec![
        "Alice -> Bob : 10 BTC",
        "Bob -> Carol : 5 BTC",
        "Carol -> Dave : 3 BTC",
        "Dave -> Eve : 1 BTC",
    ];

    println!("=== Merkle Tree Demo ===\n");
    println!("Transactions:");
    for (i, tx) in transactions.iter().enumerate() {
        println!("  TX{}: {}", i + 1, tx);
    }
    println!();

    // Compute the original Merkle Root
    let original_root = build_merkle_root(&transactions);
    println!("Merkle Root (original): {}\n", original_root);

    // Now modify TX2 to simulate tampering and see if the root changes
    println!(">>> Modifying TX2: Bob -> Carol : 5 BTC  =>  Bob -> Eve : 99 BTC\n");
    transactions[1] = "Bob -> Eve : 99 BTC";

    let tampered_root = build_merkle_root(&transactions);
    println!("Merkle Root (after tampering): {}\n", tampered_root);

    // Final comparison -- makes it obvious whether the root changed
    if original_root != tampered_root {
        println!("[DETECTED] Merkle Root changed! Tampering is evident.");
        println!("  Before : {}...", &original_root[..32]);
        println!("  After  : {}...", &tampered_root[..32]);
    } else {
        // This branch should never happen with a correct implementation
        println!("[FAILED] Root did NOT change -- something is wrong with the hash logic.");
    }
}
