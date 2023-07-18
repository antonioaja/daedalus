use anyhow::*;
use argon2::Argon2;
use console::style;
use indicatif::{ProgressBar, ProgressState, ProgressStyle};
use libaes::Cipher;
use std::fs::File;
use std::io::prelude::*;
use std::vec;

use crate::fibonacci_salter;
use crate::ui::*;

const BUFFER_SIZE: usize = 1000016;

/// Decrypts the input file
pub fn decrypt(mut file: File, args: Cli, password: String) -> Result<(), Error> {
    // Create buffers
    let mut buffer: [u8; BUFFER_SIZE] = [0; BUFFER_SIZE];
    let mut leftovers: Vec<u8> = vec![];

    // Calculate bytes in file
    let file_bytes = file
        .metadata()
        .context(format!("Could not get size of {}", &args.file))?
        .len();
    let full_chunks = (file_bytes - 80) / buffer.len() as u64;
    let leftover_bytes = (file_bytes - 80) % buffer.len() as u64;

    // Create buffers for file headers, and read into them
    let mut header: [u8; 32] = [0; 32];
    let mut input_hash: [u8; 32] = [0; 32];
    let mut iv: [u8; 16] = [0; 16];
    file.read_exact(&mut header)
        .context("Could not read header from encrypted input!")?;
    file.read_exact(&mut input_hash)
        .context("Could not read hash from encrypted input!")?;
    file.read_exact(&mut iv)
        .context("Could not read IV from encrypted input!")?;

    // Obtain the correct salt
    let salt_method: [u8; 6] = header[20..26].try_into().unwrap();
    let mut output_key = [0u8; 32];
    let salt = match &salt_method {
        b"FIBONA" => fibonacci_salter(password.len()).as_bytes().to_vec(),
        b"BLAKE3" => input_hash.to_vec(),
        _ => bail!("Invalid salting method for decryption!"),
    };

    // Using password and salt, create the cipher
    Argon2::default()
        .hash_password_into(password.as_bytes(), &salt, &mut output_key)
        .expect("Could not hash password");
    let cipher = Cipher::new_256(&output_key);

    // Create the output file
    let output_file_name = &args.file.replace(".daedalus", "");
    let mut dec_file =
        File::create(output_file_name).context(format!("Could not create {}", output_file_name))?;

    // Begin decrypting
    println!("{} {}Decrypting...", style("[1/2]").bold().dim(), FLOPPY);
    let pb = ProgressBar::new(file_bytes);
    pb.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})").unwrap().with_key("eta", |state: &ProgressState, w: &mut dyn std::fmt::Write| write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap()).progress_chars("#>-"));

    // Decrypt full chunks first
    for i in 0..full_chunks {
        file.read_exact(&mut buffer)
            .context("Could not fill buffer for file decryption!")?;
        let decrypted = cipher.cbc_decrypt(&iv, &buffer);
        dec_file
            .write_all(&decrypted)
            .context(format!("Could not write to {}", output_file_name))?;
        pb.set_position((i + 1) * buffer.len() as u64);
    }
    // Decrypt leftover bytes
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

    // Begin hashing the decrypted file
    println!(
        "{} {}Hashing decryption...",
        style("[2/2]").bold().dim(),
        POTATO
    );
    let pb = ProgressBar::new(file_bytes);
    pb.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})").unwrap().with_key("eta", |state: &ProgressState, w: &mut dyn std::fmt::Write| write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap()).progress_chars("#>-"));

    let mut dec_file = File::open(output_file_name).unwrap();
    buffer = [0; BUFFER_SIZE];
    leftovers = vec![];
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
            .context("Could not fill buffer (leftover) for file hashing after decryption!")?;
        hasher.update(&leftovers);
        pb.set_position(file_bytes);
    }

    if &input_hash != hasher.finalize().as_bytes() {
        println!("Given hash of encrypted file does not match computed hash.\nCorruption or tampering may have occurred.")
    }
    pb.finish_and_clear();
    Ok(())
}
