use anyhow::*;
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
    let cipher = Cipher::new_256(blake3::hash(args.password.as_bytes()).as_bytes());

    // Read input file into memory
    let mut file = File::open(&args.file).context(format!("Could not open {}", &args.file))?;
    let mut contents: Vec<u8> = vec![];
    file.read_to_end(&mut contents)
        .context(format!("Could not read {}", &args.file))?;

    if args.encrypt && !args.decrypt {
        // Prepend file with random 32 bytes
        for _ in 0..31 {
            contents.insert(0, rand::random::<u8>());
        }

        // Encrypt the input file
        let encrypted = cipher.cbc_encrypt(&rand::random::<u128>().to_be_bytes(), &contents);
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
        let mut decrypted = cipher.cbc_decrypt(&rand::random::<u128>().to_be_bytes(), &contents);

        // Remove garbage data
        for _ in 0..31 {
            decrypted.remove(0);
        }

        // Write out decrypted file
        let mut dec_file =
            File::create(&args.file.replace(extension(&args.file), "")).context(format!(
                "Could not create {}",
                &args.file.replace(extension(&args.file), "")
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

pub fn extension(filename: &str) -> &str {
    filename
        .rfind('.')
        .map(|idx| &filename[idx..])
        .filter(|ext| ext.chars().skip(1).all(|c| c.is_ascii_alphanumeric()))
        .unwrap_or("")
}
