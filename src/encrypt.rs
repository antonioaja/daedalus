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

const BUFFER_SIZE: usize = 1000000;

/// Encrypts the input file
pub fn encrypt(file: &mut File, args: &Cli, password: String) -> Result<(), Error> {
    let mut buffer: [u8; BUFFER_SIZE] = [0; BUFFER_SIZE];
    let mut leftovers: Vec<u8> = vec![];
    let file_bytes = file
        .metadata()
        .context(format!("Could not get size of {}", &args.file))?
        .len();
    let full_chunks = file_bytes / buffer.len() as u64;
    let leftover_bytes = file_bytes % buffer.len() as u64;
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
    let mut output_key = [0u8; 32];
    let header: [u8; 32];
    let salt = match args.salt.as_str() {
        "blake3" => {
            header = *crate::file_format::HEADER_AES256_ARGON_BLAKE3;
            hash.to_vec()
        }
        "fib" => {
            header = *crate::file_format::HEADER_AES256_ARGON_FIB;
            fibonacci_salter(password.len()).as_bytes().to_vec()
        }
        _ => bail!("Invalid salting method for encryption!"),
    };
    Argon2::default()
        .hash_password_into(password.as_bytes(), &salt, &mut output_key)
        .expect("Could not hash password");
    let cipher = Cipher::new_256(&output_key);
    let iv = rand::random::<[u8; 16]>();
    let output_file_name: &str = &(args.file.clone() + ".daedalus");
    let mut enc_file =
        File::create(output_file_name).context(format!("Could not create {}", output_file_name))?;
    enc_file
        .write_all(&header)
        .context("Could not write header to encrypted output!")?;
    enc_file
        .write_all(&hash)
        .context("Could not write file hash to encrypted output!")?;
    enc_file
        .write_all(&iv)
        .context("Could not write IV to encrypted output!")?;
    println!("{} {}Encrypting...", style("[2/2]").bold().dim(), FLOPPY);
    let pb = ProgressBar::new(file_bytes);
    pb.set_style(ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})").unwrap().with_key("eta", |state: &ProgressState, w: &mut dyn std::fmt::Write| write!(w, "{:.1}s", state.eta().as_secs_f64()).unwrap()).progress_chars("#>-"));
    file.rewind()
        .context(format!("Could not return to start of {}!", &args.file))?;
    buffer = [0u8; BUFFER_SIZE];
    leftovers = vec![];
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
    Ok(())
}
