use anyhow::*;
use argon2::Argon2;
use clap::Parser;
use console::{style, Emoji};
use indicatif::{ProgressBar, ProgressState, ProgressStyle};
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
struct Cli {
    /// The file to encrypt/decrypt
    file: String,

    /// Chooses salting method (only needs to be chosen for encryption)
    /// [OPTIONS = blake3, fib]
    #[arg(short, long, value_parser, default_value = "blake3")]
    salt: String,
}

const HEADER_AES256_ARGON_FIB: &[u8; 32] = b"DAEDALUSAES256ARGON2FIBONAglowie";
const HEADER_AES256_ARGON_BLAKE3: &[u8; 32] = b"DAEDALUSAES256ARGON2BLAKE3glowie";

static POTATO: Emoji<'_, '_> = Emoji("🥔 ", "");
static FLOPPY: Emoji<'_, '_> = Emoji("💾 ", "");

fn main() -> Result<()> {
    // Gather input arguments
    let args = Cli::parse();
    if args.salt != "blake3" && args.salt != "fib" {
        println!("Invalid salting method!\n{} is not valid.", args.salt);
        return Ok(());
    }
    let password =
        rpassword::prompt_password("Password: ").context("Unable to get password from user!")?;

    // Start timer
    let now: Instant = Instant::now();

    // Read input file into memory
    let mut file = File::open(&args.file).context(format!("Could not open {}", &args.file))?;

    if extension(&args.file) != ".daedalus" {
        // Calculate read/write operations
        let mut buffer: [u8; 1000000] = [0; 1000000];
        let mut leftovers: Vec<u8> = vec![];
        let file_bytes = file
            .metadata()
            .context(format!("Could not get size of {}", &args.file))?
            .len();
        let full_chunks = file_bytes / buffer.len() as u64;
        let leftover_bytes = file_bytes % buffer.len() as u64;

        // Hash the file
        println!("{} {}Hashing input...", style("[1/2]").bold().dim(), POTATO);
        let pb = ProgressBar::new(file_bytes);
        pb.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})").unwrap().with_key("eta", |state: &ProgressState, w: &mut dyn std::fmt::Write| write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap()).progress_chars("#>-"));
        let mut hasher = blake3::Hasher::new();
        for i in 0..full_chunks {
            file.read_exact(&mut buffer)
                .context("Could not fill buffer for file hashing before encryption!")?;
            hasher.update(&buffer);
            pb.set_position((i + 1) * buffer.len() as u64);
        }
        if leftover_bytes != 0 {
            file.read_to_end(&mut leftovers)
                .context("Could not fill buffer for file hashing before encryption!")?;
            hasher.update(&leftovers);
            pb.set_position(file_bytes)
        }
        let hash: [u8; 32] = *hasher.finalize().as_bytes();
        pb.finish_and_clear();

        // Create cipher
        let mut output_key = [0u8; 32];
        let header: [u8; 32];
        let salt = match args.salt.as_str() {
            "blake3" => {
                header = *HEADER_AES256_ARGON_BLAKE3;
                hash.to_vec()
            }
            "fib" => {
                header = *HEADER_AES256_ARGON_FIB;
                fibonacci_salter(password.len()).as_bytes().to_vec()
            }
            _ => bail!("Invalid salting method for encryption!"),
        };
        Argon2::default()
            .hash_password_into(password.as_bytes(), &salt, &mut output_key)
            .expect("Could not hash password");
        let cipher = Cipher::new_256(&output_key);

        // Calculate random IV
        let iv = rand::random::<[u8; 16]>();

        // Create the output file
        let output_file_name: &str = &(args.file.clone() + ".daedalus");
        let mut enc_file = File::create(output_file_name)
            .context(format!("Could not create {}", output_file_name))?;

        // Insert header, file hash, & IV
        enc_file
            .write_all(&header)
            .context("Could not write header to encrypted output!")?;
        enc_file
            .write_all(&hash)
            .context("Could not write file hash to encrypted output!")?;
        enc_file
            .write_all(&iv)
            .context("Could not write IV to encrypted output!")?;

        // Encrypt the file
        println!("{} {}Encrypting...", style("[2/2]").bold().dim(), FLOPPY);
        let pb = ProgressBar::new(file_bytes);
        pb.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})").unwrap().with_key("eta", |state: &ProgressState, w: &mut dyn std::fmt::Write| write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap()).progress_chars("#>-"));
        file.rewind()
            .context(format!("Could not return to start of {}!", &args.file))?;
        let mut buffer: [u8; 1000000] = [0; 1000000];
        let mut leftovers: Vec<u8> = vec![];
        for i in 0..full_chunks {
            file.read_exact(&mut buffer)
                .context("Could not fill buffer for file encryption!")?;
            let encrypted = cipher.cbc_encrypt(&iv, &buffer);
            enc_file
                .write_all(&encrypted)
                .context(format!("Could not write to {}", output_file_name))?;
            pb.set_position((i + 1) * buffer.len() as u64)
        }
        if leftover_bytes != 0 {
            file.read_to_end(&mut leftovers)
                .context("Could not fill buffer for file encryption!")?;
            let encrypted = cipher.cbc_encrypt(&iv, &leftovers);
            enc_file
                .write_all(&encrypted)
                .context(format!("Could not write to {}", output_file_name))?;
            pb.set_position(file_bytes);
        }
        pb.finish_and_clear();
    } else if extension(&args.file) == ".daedalus" {
        // Calculate read/write operations
        let mut buffer: [u8; 1000016] = [0; 1000016];
        let mut leftovers: Vec<u8> = vec![];
        let file_bytes = file
            .metadata()
            .context(format!("Could not get size of {}", &args.file))?
            .len();
        let full_chunks = (file_bytes - 80) / buffer.len() as u64;
        let leftover_bytes = (file_bytes - 80) % buffer.len() as u64;

        // Read header information
        let mut header: [u8; 32] = [0; 32];
        let mut input_hash: [u8; 32] = [0; 32];
        let mut iv: [u8; 16] = [0; 16];
        file.read_exact(&mut header)
            .context("Could not read header from encrypted input!")?;
        file.read_exact(&mut input_hash)
            .context("Could not read hash from encrypted input!")?;
        file.read_exact(&mut iv)
            .context("Could not read IV from encrypted input!")?;
        let salt_method: [u8; 6] = header[20..26].try_into().unwrap();

        // Create cipher
        let mut output_key = [0u8; 32];
        let salt = match &salt_method {
            b"FIBONA" => fibonacci_salter(password.len()).as_bytes().to_vec(),
            b"BLAKE3" => input_hash.to_vec(),
            _ => bail!("Invalid salting method for decryption!"),
        };
        Argon2::default()
            .hash_password_into(password.as_bytes(), &salt, &mut output_key)
            .expect("Could not hash password");
        let cipher = Cipher::new_256(&output_key);

        // Create the output file
        let output_file_name = &args.file.replace(".daedalus", "");
        let mut dec_file = File::create(output_file_name)
            .context(format!("Could not create {}", output_file_name))?;

        // Decrypt the file
        println!("{} {}Decrypting...", style("[1/2]").bold().dim(), FLOPPY);
        let pb = ProgressBar::new(file_bytes);
        pb.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})").unwrap().with_key("eta", |state: &ProgressState, w: &mut dyn std::fmt::Write| write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap()).progress_chars("#>-"));
        for i in 0..full_chunks {
            file.read_exact(&mut buffer)
                .context("Could not fill buffer for file decryption!")?;
            let decrypted = cipher.cbc_decrypt(&iv, &buffer);
            dec_file
                .write_all(&decrypted)
                .context(format!("Could not write to {}", output_file_name))?;
            pb.set_position((i + 1) * buffer.len() as u64);
        }
        if leftover_bytes != 0 {
            file.read_to_end(&mut leftovers)
                .context("Could not fill buffer for file decryption!")?;
            let decrypted = cipher.cbc_decrypt(&iv, &leftovers);
            dec_file
                .write_all(&decrypted)
                .context(format!("Could not write to {}", output_file_name))?;
            pb.set_position(file_bytes);
        }
        pb.finish_and_clear();

        // Calculate and compare hashes
        println!(
            "{} {}Hashing decryption...",
            style("[2/2]").bold().dim(),
            POTATO
        );
        let pb = ProgressBar::new(file_bytes);
        pb.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})").unwrap().with_key("eta", |state: &ProgressState, w: &mut dyn std::fmt::Write| write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap()).progress_chars("#>-"));
        let mut dec_file = File::open(output_file_name).unwrap();
        let mut buffer: [u8; 1000016] = [0; 1000016];
        let mut leftovers: Vec<u8> = vec![];
        let mut hasher = blake3::Hasher::new();
        for i in 0..full_chunks {
            dec_file
                .read_exact(&mut buffer)
                .context("Could not fill buffer for file hashing after decryption!")?;
            hasher.update(&buffer);
            pb.set_position((i + 1) * buffer.len() as u64);
        }
        if leftover_bytes != 0 {
            dec_file
                .read_to_end(&mut leftovers)
                .context("Could not fill buffer for file hashing after decryption!")?;
            hasher.update(&leftovers);
            pb.set_position(file_bytes);
        }
        if &input_hash != hasher.finalize().as_bytes() {
            println!("Given hash of encrypted file does not match computed hash.\nCorruption or tampering may have occurred.")
        }
        pb.finish_and_clear();
    } else {
        println!("Something went wrong! Invalid extension.\nThis should be impossible. Contact developer.");
    }

    println!("Overall Time Elapsed: {} ms", now.elapsed().as_millis());

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
        out_salt += "0";
    }

    out_salt
}

pub fn extension(filename: &str) -> &str {
    filename
        .rfind('.')
        .map(|idx| &filename[idx..])
        .filter(|ext| ext.chars().skip(1).all(|c| c.is_ascii_alphanumeric()))
        .unwrap_or("")
}
