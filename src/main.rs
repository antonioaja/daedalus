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
    /// The file to encrypt
    #[clap(short, long, value_parser)]
    input: String,

    /// Password to encrypt with
    #[clap(short, long, value_parser)]
    password: String,
}

fn main() -> Result<()> {
    let args: Args = Args::parse();

    let mut file = File::open(&args.input).context(format!("Could not open {}", &args.input))?;
    let mut contents: Vec<u8> = vec![];
    file.read_to_end(&mut contents)
        .context(format!("Could not read {}", &args.input))?;

    let cipher = Cipher::new_256(blake3::hash(args.input.as_bytes()).as_bytes());

    let encrypted = cipher.cbc_encrypt(&rand::random::<u128>().to_be_bytes(), &contents);
    let mut enc_file = File::create(args.input.clone() + ".daedalus").context(format!(
        "Could not create {}",
        args.input.clone() + ".daedalus"
    ))?;
    enc_file.write_all(&encrypted).context(format!(
        "Could not write to {}",
        args.input.clone() + ".daedalus"
    ))?;

    let mut inter_file = File::open(args.input.clone() + ".daedalus").context(format!(
        "Could not open {}",
        args.input.clone() + ".daedalus"
    ))?;
    let mut contents: Vec<u8> = vec![];
    inter_file.read_to_end(&mut contents).context(format!(
        "Could not read {}",
        args.input.clone() + ".daedalus"
    ))?;
    let decrypted = cipher.cbc_decrypt(&rand::random::<u128>().to_be_bytes(), &contents);

    let mut dec_file = File::create("dec_".to_owned() + &args.input.clone()).context(format!(
        "Could not create {}",
        "dec_".to_owned() + &args.input.clone()
    ))?;
    dec_file.write_all(&decrypted).context(format!(
        "Could not write to {}",
        "dec_".to_owned() + &args.input.clone()
    ))?;

    Ok(())
}
