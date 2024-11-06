use argon2::Argon2;
use hmac::{Hmac, Mac};

use sha2::Sha256;
use rand::Rng;

use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::process;

type HmacSha256 = Hmac<Sha256>;

const NONCE_SIZE: usize = 64; // Increase nonce to 64 bytes for increased entropy
const MAC_SIZE: usize = 32;   // Size of HMAC-SHA256 output

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

    let mut key = Vec::new();
    if let Err(err) = load_key(&mut key, key_file) {
        eprintln!("Failed to load key: {}", err);
        process::exit(1);
    }

    let mut input_data = Vec::new();
    if let Err(err) = load_file(input_file, &mut input_data) {
        eprintln!("Failed to load input file: {}", err);
        process::exit(1);
    }

    if key.len() < input_data.len() {
        eprintln!("The key is too short.");
        process::exit(1);
    }

    let mut output_data = Vec::new();
    match mode.as_str() {
        "E" => {
            let nonce = generate_random_bytes(NONCE_SIZE);
            let iv = derive_iv_with_argon2(&nonce, input_data.len());
            output_data.extend_from_slice(&nonce); // Prepend the nonce to the output
            xor_encrypt_decrypt_with_iv(&input_data, &key, &iv, &mut output_data);
            let mac = generate_hmac(&key, &output_data);
            output_data.extend_from_slice(&mac); // Append HMAC to the output
        }
        "D" => {
            if input_data.len() < NONCE_SIZE + MAC_SIZE {
                eprintln!("Invalid input file: missing nonce or MAC.");
                process::exit(1);
            }
            let (nonce, rest) = input_data.split_at(NONCE_SIZE);
            let (encrypted_data, received_mac) = rest.split_at(rest.len() - MAC_SIZE);
            let iv = derive_iv_with_argon2(nonce, encrypted_data.len());
            verify_hmac(&key, &input_data[..input_data.len() - MAC_SIZE], received_mac);
            xor_encrypt_decrypt_with_iv(encrypted_data, &key, &iv, &mut output_data);
        }
        _ => unreachable!(),
    }

    if let Err(err) = save_file(output_file, &output_data) {
        eprintln!("Failed to save output file: {}", err);
        process::exit(1);
    }
}

fn load_key(key: &mut Vec<u8>, key_file: &str) -> std::io::Result<()> {
    let mut file = File::open(key_file)?;
    file.read_to_end(key)?;
    Ok(())
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

fn derive_iv_with_argon2(nonce: &[u8], length: usize) -> Vec<u8> {
    
    let argon2 = Argon2::default();
    let mut iv = vec![0u8; length];
    argon2.hash_password_into(nonce, nonce, &mut iv).expect("Failed to derive IV using Argon2");
    iv
}

fn xor_encrypt_decrypt_with_iv(input: &[u8], key: &[u8], iv: &[u8], output: &mut Vec<u8>) {
    if key.len() < input.len() {
        eprintln!("Key length must be at least as long as the input length.");
        process::exit(1);
    }

    for (i, &byte) in input.iter().enumerate() {
        let iv_byte = iv[i];  // Use the full-length IV derived with Argon2
        let key_byte = key[i];          // Use the key byte-for-byte without repeating
        output.push(byte ^ key_byte ^ iv_byte);
    }
}

fn generate_hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("Failed to create HMAC");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn verify_hmac(key: &[u8], data: &[u8], received_mac: &[u8]) {
    let mut mac = HmacSha256::new_from_slice(key).expect("Failed to create HMAC");
    mac.update(data);
    if mac.verify_slice(received_mac).is_err() {
        eprintln!("MAC verification failed. Data may have been tampered with.");
        process::exit(1);
    }
}
