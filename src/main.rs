use anyhow::*;
use argon2::Argon2;
use clap::Parser;
use libaes::Cipher;
use std::fs::File;
use std::io::prelude::*;

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

    /// Encrypts the input
    #[clap(short, long, value_parser, default_value_t = false)]
    encrypt: bool,

    /// Decrypts the input
    #[clap(short, long, value_parser, default_value_t = false)]
    decrypt: bool,
}

fn main() -> Result<()> {
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
    let mut contents: Vec<u8> = vec![];
    file.read_to_end(&mut contents)
        .context(format!("Could not read {}", &args.file))?;

    if args.encrypt && !args.decrypt {
        // Prepend file with IV data (random 16 bytes)
        let iv = rand::random::<[u8; 16]>();

        for i in 0..16 {
            contents.insert(i, iv[i]);
        }

        // Encrypt the input file
        let encrypted = cipher.cbc_encrypt(&iv, &contents);
        let mut enc_file = File::create(args.file.clone() + ".daedalus").context(format!(
            "Could not create {}",
            args.file.clone() + ".daedalus"
        ))?;
        enc_file.write_all(&encrypted).context(format!(
            "Could not write to {}",
            args.file.clone() + ".daedalus"
        ))?;
    } else if args.decrypt && !args.encrypt {
        // Decrypt the input file
        let mut decrypted = cipher.cbc_decrypt(&contents[0..16], &contents);

        // Remove IV data
        for _ in 0..16 {
            decrypted.remove(0);
        }

        // Write out decrypted file
        let mut dec_file = File::create(&args.file.replace(".daedalus", "")).context(format!(
            "Could not create {}",
            &args.file.replace(".daedalus", "")
        ))?;
        dec_file.write_all(&decrypted).context(format!(
            "Could not write to {}",
            "dec_".to_owned() + &args.file.clone()
        ))?;
    } else {
        println!("The option to decrypt or encrypt wasn't selected, or both were selected.\nPlease pick one!");
    }

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
