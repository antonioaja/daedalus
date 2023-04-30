use anyhow::*;
use argon2::Argon2;
use clap::Parser;
use libaes::Cipher;
use std::fs::File;
use std::io::prelude::*;
use std::time::*;

#[derive(Parser, Debug)]
#[clap(
    author = "Antonio Aguilar",
    version,
    about = "A CLI program to encrypt/decrypt files"
)]
struct Args {
    /// The file to encrypt/decrypt
    #[clap(short, long, value_parser)]
    file: String,

    /// Password to encrypt/decrypt with
    #[clap(short, long, value_parser)]
    password: String,

    /// Activates verbose output
    #[clap(short, long, value_parser, default_value_t = false)]
    verbose: bool,
}

const HEADER_AES256_ARGON_FIB: &[u8; 32] = b"DAEDALUSAES256ARGON2FIBONAglowie";

fn main() -> Result<()> {
    // Start timer
    let now: Instant = Instant::now();

    // Gather input arguments
    let args: Args = Args::parse();

    // Create cipher
    let mut output_key = [0u8; 32];
    Argon2::default()
        .hash_password_into(
            args.password.as_bytes(),
            fibonacci_salter(args.password.len()).as_bytes(),
            &mut output_key,
        )
        .expect("Could not hash password");
    let cipher = Cipher::new_256(&output_key);

    // Read input file into memory
    let mut file = File::open(&args.file).context(format!("Could not open {}", &args.file))?;

    if extension(&args.file) != ".daedalus" {
        // Calculate read/write operations
        let mut buffer: [u8; 1000000] = [0; 1000000];
        let mut leftovers: Vec<u8> = vec![];
        let file_bytes = file.metadata().unwrap().len();
        let full_chunks = file_bytes / buffer.len() as u64;
        let leftover_bytes = file_bytes % buffer.len() as u64;

        // Hash the file
        let mut hasher = blake3::Hasher::new();
        for _ in 0..full_chunks {
            file.read_exact(&mut buffer).expect("Could not fill buffer");
            hasher.update(&buffer);
        }
        if leftover_bytes != 0 {
            file.read_to_end(&mut leftovers)
                .expect("Could not fill buffer");
            hasher.update(&leftovers);
        }
        let hash: [u8; 32] = hasher.finalize().as_bytes().clone();

        // Calculate random IV
        let iv = rand::random::<[u8; 16]>();

        // Create the output file
        let mut enc_file = File::create(args.file.clone() + ".daedalus").context(format!(
            "Could not create {}",
            args.file.clone() + ".daedalus"
        ))?;

        // Insert header, file hash, & IV
        enc_file
            .write_all(HEADER_AES256_ARGON_FIB)
            .expect("Could not write header to output!");
        enc_file
            .write_all(&hash)
            .expect("Could not write file hash to output!");
        enc_file
            .write_all(&iv)
            .expect("Could not write IV to output!");

        // Encrypt the file
        file.rewind().expect("Could not return to start of file!");
        let mut buffer: [u8; 1000000] = [0; 1000000];
        let mut leftovers: Vec<u8> = vec![];
        for _ in 0..full_chunks {
            file.read_exact(&mut buffer).expect("Could not fill buffer");
            let encrypted = cipher.cbc_encrypt(&iv, &buffer);
            enc_file.write_all(&encrypted).context(format!(
                "Could not write to {}",
                args.file.clone() + ".daedalus"
            ))?;
        }
        if leftover_bytes != 0 {
            file.read_to_end(&mut leftovers)
                .expect("Could not fill buffer");
            let encrypted = cipher.cbc_encrypt(&iv, &leftovers);
            enc_file.write_all(&encrypted).context(format!(
                "Could not write to {}",
                args.file.clone() + ".daedalus"
            ))?;
        }
    } else if extension(&args.file) == ".daedalus" {
        // Calculate read/write operations
        let mut buffer: [u8; 1000016] = [0; 1000016];
        let mut leftovers: Vec<u8> = vec![];
        let file_bytes = file.metadata().unwrap().len();
        let full_chunks = (file_bytes - 80) / buffer.len() as u64;
        let leftover_bytes = (file_bytes - 80) % buffer.len() as u64;

        // Read header information
        let mut header: [u8; 32] = [0; 32];
        let mut input_hash: [u8; 32] = [0; 32];
        let mut iv: [u8; 16] = [0; 16];
        file.read_exact(&mut header)
            .expect("Could not read header!");
        file.read_exact(&mut input_hash)
            .expect("Could not read hash!");
        file.read_exact(&mut iv).expect("Could not read IV!");

        // Create the output file
        let mut dec_file = File::create(&args.file.replace(".daedalus", "")).context(format!(
            "Could not create {}",
            &args.file.replace(".daedalus", "")
        ))?;

        // Decrypt the file
        for _ in 0..full_chunks {
            file.read_exact(&mut buffer).expect("Could not fill buffer");
            let decrypted = cipher.cbc_decrypt(&iv, &buffer);
            dec_file.write_all(&decrypted).context(format!(
                "Could not write to {}",
                args.file.clone() + ".daedalus"
            ))?;
        }
        if leftover_bytes != 0 {
            file.read_to_end(&mut leftovers)
                .expect("Could not fill buffer");
            let decrypted = cipher.cbc_decrypt(&iv, &leftovers);
            dec_file.write_all(&decrypted).context(format!(
                "Could not write to {}",
                args.file.clone() + ".daedalus"
            ))?;
        }

        // Calculate and compare hashes
        let mut dec_file = File::open(&args.file.replace(".daedalus", "")).unwrap();
        let mut buffer: [u8; 1000016] = [0; 1000016];
        let mut leftovers: Vec<u8> = vec![];
        let mut hasher = blake3::Hasher::new();
        for _ in 0..full_chunks {
            dec_file
                .read_exact(&mut buffer)
                .expect("Could not fill buffer");
            hasher.update(&buffer);
        }
        if leftover_bytes != 0 {
            dec_file
                .read_to_end(&mut leftovers)
                .expect("Could not fill buffer");
            hasher.update(&leftovers);
        }
        if &input_hash != hasher.finalize().as_bytes() {
            println!("Given hash of encrypted file does not match computed hash.\nCorruption or tampering may have occurred.")
        }
    } else {
        println!("Something went wrong! Invalid extension.\nThis should be impossible. Contact developer.");
    }

    println!("\nTime Elapsed: {} ms", now.elapsed().as_millis());

    Ok(())
}

pub fn fibonacci_salter(pwd_len: usize) -> String {
    let mut out_salt = String::new();

    if pwd_len == 0 {
        out_salt.insert(0, '0');
    } else if pwd_len == 1 {
        out_salt.insert(0, '1');
    } else {
        let mut last: u64 = 0;
        let mut curr: u64 = 1;

        out_salt.insert(0, '1');

        for _ in 1..pwd_len {
            let sum: u64 = last + curr;
            last = curr;
            curr = sum;

            out_salt = out_salt + &curr.to_string();
        }
    }

    while out_salt.len() < 8 {
        out_salt = out_salt + "0";
    }

    return out_salt;
}

pub fn extension(filename: &str) -> &str {
    filename
        .rfind('.')
        .map(|idx| &filename[idx..])
        .filter(|ext| ext.chars().skip(1).all(|c| c.is_ascii_alphanumeric()))
        .unwrap_or("")
}
