use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::{Digest, Sha256};

use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::process;

type HmacSha256 = Hmac<Sha256>;

const NONCE_SIZE: usize = 16; // 128-bit nonce
const MAC_SIZE: usize = 32;   // HMAC-SHA256 output size

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        eprintln!("Usage: <E|D> <input_file> <output_file> <key_file>");
        process::exit(1);
    }

    let mode = &args[1];
    let input_file = &args[2];
    let output_file = &args[3];
    let key_file = &args[4];

    if mode != "E" && mode != "D" {
        eprintln!("Invalid mode. Use 'E' for encrypt or 'D' for decrypt.");
        process::exit(1);
    }

    // Prevent overwriting the key file
    if file_exists(output_file) {
        eprintln!(
            "Output file '{}' already exists. Aborting to prevent overwrite.",
            output_file
        );
        process::exit(1);
    }

    let mut key = Vec::new();
    if let Err(err) = load_file(key_file, &mut key) {
        eprintln!("Failed to load key: {}", err);
        process::exit(1);
    }

    let mut input_data = Vec::new();
    if let Err(err) = load_file(input_file, &mut input_data) {
        eprintln!("Failed to load input file: {}", err);
        process::exit(1);
    }

    // Adjust key length validation based on mode
    if (mode == "E" && key.len() < input_data.len()) ||
       (mode == "D" && key.len() < input_data.len().saturating_sub(NONCE_SIZE + MAC_SIZE)) {
        eprintln!("The key is too short.");
        process::exit(1);
    }

    let mut output_data = Vec::new();
    match mode.as_str() {
        "E" => {
            let nonce = generate_random_bytes(NONCE_SIZE);
            let keystream = generate_keystream(&nonce, input_data.len());
            output_data.extend_from_slice(&nonce); // Prepend the nonce

            let mut temp_data = Vec::new();
            xor_with_key_and_keystream(&input_data, &key, &keystream, &mut temp_data);
            output_data.extend_from_slice(&temp_data);

            let hmac_key = derive_hmac_key(&key);
            let mac = generate_hmac(&hmac_key, &output_data);
            output_data.extend_from_slice(&mac); // Append HMAC
        }
        "D" => {
            if input_data.len() < NONCE_SIZE + MAC_SIZE {
                eprintln!("Invalid input file: missing nonce or MAC.");
                process::exit(1);
            }

            let (nonce, rest) = input_data.split_at(NONCE_SIZE);
            let (ciphertext, received_mac) = rest.split_at(rest.len() - MAC_SIZE);

            let hmac_key = derive_hmac_key(&key);
            verify_hmac(&hmac_key, &input_data[..input_data.len() - MAC_SIZE], received_mac);

            let keystream = generate_keystream(nonce, ciphertext.len());
            xor_with_key_and_keystream(ciphertext, &key, &keystream, &mut output_data);
        }
        _ => unreachable!(),
    }

    if let Err(err) = save_file(output_file, &output_data) {
        eprintln!("Failed to save output file: {}", err);
        process::exit(1);
    }
}

fn load_file(filename: &str, buffer: &mut Vec<u8>) -> std::io::Result<()> {
    let mut file = File::open(filename)?;
    file.read_to_end(buffer)?;
    Ok(())
}

fn save_file(filename: &str, data: &[u8]) -> std::io::Result<()> {
    let mut file = File::create(filename)?;
    file.write_all(data)?;
    Ok(())
}

fn generate_random_bytes(size: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..size).map(|_| rng.gen::<u8>()).collect()
}

fn generate_keystream(nonce: &[u8], length: usize) -> Vec<u8> {
    let mut keystream = Vec::with_capacity(length);
    let mut counter = 0u64;

    while keystream.len() < length {
        let mut hasher = Sha256::new();
        hasher.update(nonce);
        hasher.update(&counter.to_be_bytes());
        let hash_output = hasher.finalize();
        let chunk = if keystream.len() + hash_output.len() > length {
            &hash_output[..length - keystream.len()]
        } else {
            &hash_output[..]
        };
        keystream.extend_from_slice(chunk);
        counter += 1;
    }

    keystream
}

fn xor_with_key_and_keystream(
    input: &[u8],
    key: &[u8],
    keystream: &[u8],
    output: &mut Vec<u8>,
) {
    for i in 0..input.len() {
        let byte = input[i] ^ key[i] ^ keystream[i];
        output.push(byte);
    }
}

fn derive_hmac_key(key: &[u8]) -> Vec<u8> {
    // Derive a separate HMAC key from the key file using SHA-256
    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.finalize().to_vec()
}

fn generate_hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn verify_hmac(key: &[u8], data: &[u8], received_mac: &[u8]) {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    if mac.verify_slice(received_mac).is_err() {
        eprintln!("MAC verification failed. Data may have been tampered with.");
        process::exit(1);
    }
}

// Added Function to Check if a File Exists
fn file_exists(filename: &str) -> bool {
    Path::new(filename).exists()
}
