use sha2::{Sha256, Digest};

// A single block in the chain.
// I'm keeping it simple -- index, data, previous hash, and its own hash.
struct Block {
    index: u32,
    data: String,
    prev_hash: String,
    hash: String,
}

// Compute the SHA-256 hash for a block given its fields.
// Concatenating index + data + prev_hash as the input feels natural and easy to follow.
fn compute_hash(index: u32, data: &str, prev_hash: &str) -> String {
    let input = format!("{}{}{}", index, data, prev_hash);
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

impl Block {
    // Build a new block and immediately compute its hash.
    fn new(index: u32, data: &str, prev_hash: &str) -> Block {
        let hash = compute_hash(index, data, prev_hash);
        Block {
            index,
            data: data.to_string(),
            prev_hash: prev_hash.to_string(),
            hash,
        }
    }

    // Print a quick summary of the block so we can see what's inside.
    fn print_info(&self) {
        println!("  Block #{}", self.index);
        println!("    Data      : {}", self.data);
        println!("    Prev Hash : {}", &self.prev_hash[..16]);  // just show first 16 chars
        println!("    Own Hash  : {}", &self.hash[..16]);
        println!();
    }
}

// Walk through every block in the chain and check two things:
//   1. Does its stored hash still match what we'd compute fresh from its data?
//   2. Does its prev_hash match the actual hash of the block before it?
// If either check fails we flag it as tampered.
fn check_integrity(chain: &Vec<Block>) {
    println!("--- Running integrity check ---");
    let mut all_good = true;

    for i in 0..chain.len() {
        let block = &chain[i];
        let expected_hash = compute_hash(block.index, &block.data, &block.prev_hash);

        if block.hash != expected_hash {
            println!(
                "[TAMPERED] Block #{} has a bad hash! Stored: {}... Expected: {}...",
                block.index,
                &block.hash[..16],
                &expected_hash[..16]
            );
            all_good = false;
        } else if i > 0 && block.prev_hash != chain[i - 1].hash {
            println!(
                "[BROKEN LINK] Block #{} doesn't link back to Block #{} correctly.",
                block.index,
                chain[i - 1].index
            );
            all_good = false;
        } else {
            println!("[OK] Block #{} looks fine.", block.index);
        }
    }

    if all_good {
        println!("All blocks are intact. Chain is valid.");
    } else {
        println!("Chain integrity is COMPROMISED.");
    }
    println!();
}

fn main() {
    // Build the genesis block first (no previous block, so prev_hash is all zeros).
    let genesis = Block::new(0, "Genesis Block -- chain starts here", "0000000000000000");
    let block1 = Block::new(1, "Alice sends 50 BTC to Bob", &genesis.hash);
    let block2 = Block::new(2, "Bob sends 20 BTC to Carol", &block1.hash);

    let mut chain: Vec<Block> = vec![genesis, block1, block2];

    // Print the chain as-built.
    println!("=== Blockchain (original) ===\n");
    for b in &chain {
        b.print_info();
    }

    // Verify everything looks clean before touching anything.
    check_integrity(&chain);

    // Now simulate tampering: someone quietly changes Block 1's transaction data
    // without recalculating the hash. This is the classic attack scenario.
    println!(">>> Tampering with Block #1 -- changing transaction data...\n");
    chain[1].data = "Alice sends 50 BTC to Eve".to_string(); // <-- attacker's change

    // Run the check again. Block 1 should now fail.
    check_integrity(&chain);
}
