#![allow(unused)]
use base64::encode;
use log::debug;
use std::{
    cmp::Ordering::Equal, collections::HashMap, mem, ptr::write_bytes, slice::Chunks,
    str::from_utf8,
};
mod challenge_data;

fn main() {
    env_logger::init();
    set_1_c_1();
    set_1_c_2();
    set_1_c_3();
    set_1_c_4();
    set_1_c_5();
    set_1_c_6();
    set_1_c_7();
}

fn set_1_c_7() {
    debug!("Set 1, Challenge 7");
    let bytes = base64::decode(challenge_data::S_1_C_7.replace('\n', "")).unwrap();
    
    debug!("");
}

/// Break repeating-key XOR
fn set_1_c_6() {
    debug!("Set 1, Challenge 6");
    let bytes = base64::decode(challenge_data::S_1_C_6.replace('\n', "")).unwrap();
    assert_eq!(
        37,
        hamming_distance_str_bit_level("this is a test", "wokka wokka!!!")
    );
    debug!(r#"bit level Hamming distance between "this is a test" and "wokka wokka!!!" is 37"#);

    let mut distances_for_keysizes: Vec<(f64, usize)> = vec![];
    (1..=40).for_each(|keysize| {
        let mut iter = bytes.clone().into_iter().step_by(keysize);
        let b1 = iter.next().unwrap();
        let b2 = iter.next().unwrap();
        let distance = hamming_distance(&b1, &b2);
        let normalized: f64 = distance as f64 / keysize as f64;
        distances_for_keysizes.push((normalized, keysize));
    });

    distances_for_keysizes
        .sort_by(|(dist_1, _), (dist_2, _)| dist_1.partial_cmp(dist_2).unwrap_or(Equal));
    // debug!("All keysizes {:?}", distances_for_keysizes);

    let mut keys: HashMap<usize, String> = HashMap::new();
    // TODO: figure out why the winning key is so deep into the sorted results
    (0..40).for_each(|n| {
        //  Now that you probably know the KEYSIZE: break the ciphertext
        //  into blocks of KEYSIZE length.
        let keysize = distances_for_keysizes[n].1;
        let blocks: Vec<&[u8]> = bytes.chunks_exact(keysize).collect();

        //  Now transpose the blocks: make a block that is the first
        //  byte of every block, and a block that is the second byte
        //  of every block, and so on.
        let mut transposed_blocks: Vec<Vec<u8>> = vec![vec![]; keysize];
        for byte in (0..keysize) {
            blocks.iter().for_each(|block| {
                transposed_blocks[byte].push(block[byte]);
            })
        }

        // Solve each block as if it was single-character XOR.
        let mut key = String::new();
        for slice in transposed_blocks {
            // For each block, the single-byte XOR key that produces
            // the best histogram is the repeating-key XOR key byte
            // for that block. Put them together and you have the key
            let best_english = find_english_for_single_char_xor(&slice);
            key.push(best_english.1 as char);
        }
        keys.insert(keysize, key);
    });

    // The only good looking one is for keysize 29
    let key = keys.get(&29).unwrap();
    debug!("{}", key);
    let repeat: String = key.chars().cycle().take(bytes.len()).collect();
    let decrypted = xor(&bytes, repeat.as_bytes());
    debug!("");
    print_as_utf8(&decrypted);
    debug!("");
}

/// Implement repeating-key XOR
fn set_1_c_5() {
    debug!("Set 1, Challenge 5");

    let stanza: &str = r#"Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"#;

    let ice: String = "ICE".chars().cycle().take(stanza.len()).collect();
    let result = xor(stanza.as_bytes(), ice.as_bytes());
    let hex = bytes_to_hex(&result);
    assert_eq!("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f", hex);
    debug!("encryption of stanza succesful");
    debug!("");
}

/// Detect single-character XOR
fn set_1_c_4() {
    debug!("Set 1, Challenge 4");

    let results: Vec<(usize, u8, Vec<u8>)> = challenge_data::S_1_C_4
        .lines()
        .map(|line| find_english_for_single_char_xor(&hex_to_bytes(line)))
        .collect();

    let best_english = results
        .iter()
        .max_by(|(score_a, _, _), (score_b, _, _)| score_a.cmp(score_b))
        .unwrap();

    debug!(
        "secret character used to encrypt: {}",
        (best_english.1 as char)
    );
    debug!("message:");
    print_as_utf8(&best_english.2);

    debug!("");
}

/// Single-byte XOR cipher
fn set_1_c_3() {
    debug!("Set 1, Challenge 3");
    let h1 = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let b1 = hex_to_bytes(h1);

    let best_english: (usize, u8, Vec<u8>) = find_english_for_single_char_xor(&b1);

    debug!(
        "secret character used to encrypt: {}",
        (best_english.1 as char)
    );
    debug!("message:");
    print_as_utf8(&best_english.2);

    debug!("");
}

/// Fixed XOR
/// This problem illustrates the vulnerability of re-using a secret.
/// See Crypto101, chapter 5.5: Attacks on “one-time pads”
/// https://raw.githubusercontent.com/crypto101/crypto101.github.io/master/Crypto101.pdf
fn set_1_c_2() {
    // Suppose an attacker gets two ciphertexts with the same
    // “one-time” pad. The attacker can then XOR the two ciphertexts,
    // which is also the XOR of the plaintexts:

    debug!("Set 1, Challenge 2");
    let h1 = "1c0111001f010100061a024b53535009181c";
    let h2 = "686974207468652062756c6c277320657965";
    let b1 = hex_to_bytes(h1);
    let b2 = hex_to_bytes(h2);

    // print_as_utf8(&bytes) // garbled, cipher text
    print_as_utf8(&b2);

    let secret = xor(&b1, &b2);
    print_as_utf8(&secret);

    let hex_secret = bytes_to_hex(&secret);
    assert_eq!("746865206b696420646f6e277420706c6179", hex_secret);
    debug!("");
}

/// Convert hex to base64
fn set_1_c_1() {
    debug!("Set 1, Challenge 1");
    let p = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let bytes: Vec<u8> = hex_to_bytes(p);
    print_as_utf8(&bytes);
    let b64 = encode(bytes);
    assert_eq!(
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
        b64
    );
    debug!("");
}

// Utility Functions

fn bits(byte: &u8) -> [u8; 8] {
    let mut bits: [u8; 8] = [0; 8];

    (0..8).for_each(|i| {
        bits[i] = (byte >> i) & 1;
    });
    bits
}

fn hamming_distance_str_bit_level(s1: &str, s2: &str) -> usize {
    assert_eq!(s1.len(), s2.len());
    s1.as_bytes()
        .iter()
        .zip(s2.as_bytes().iter())
        .map(|(char1, char2)| {
            let bits1 = bits(char1).into_iter();
            let bits2 = bits(char2).into_iter();
            bits1.zip(bits2).filter(|(b1, b2)| b1 != b2).count()
        })
        .sum()
}

// bit level edit/Hamming distance
fn hamming_distance(byte_1: &u8, byte_2: &u8) -> usize {
    let bits1 = bits(byte_1).into_iter();
    let bits2 = bits(byte_2).into_iter();
    bits1.zip(bits2).filter(|(b1, b2)| b1 != b2).count()
}

fn print_as_utf8(bytes: &[u8]) {
    let s = from_utf8(bytes).unwrap();
    s.lines().for_each(|l| debug!("{}", l));
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let bytes: Vec<u8> = hex
        .as_bytes()
        .chunks(2)
        .map(|chunk| u8::from_str_radix(from_utf8(chunk).unwrap(), 16).unwrap())
        .collect();
    bytes
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::new(), |acc, b| acc + (&format!("{:02x}", b)))
}

fn xor(bytes: &[u8], bytes_2: &[u8]) -> Vec<u8> {
    assert_eq!(bytes.len(), bytes_2.len());
    bytes.iter().zip(bytes_2).map(|(a, b)| a ^ b).collect()
}

/// XORs a string with every possible character that fits in 1 byte;
/// Returns a tuple of (score, xor_char, message)
fn find_english_for_single_char_xor(bytes: &[u8]) -> (usize, u8, Vec<u8>) {
    let mut best_english: (usize, u8, Vec<u8>) = (0, 0, vec![0]);
    for c in 0..=255 {
        let single_char_mask = vec![c; bytes.len()];
        let crack = xor(bytes, &single_char_mask);
        let score = crack
            .iter()
            .filter(|ch| "etaoin shrdlu".as_bytes().contains(ch))
            .count();

        if best_english.0 < score {
            best_english = (score, c, crack);
        }
    }
    best_english
}
