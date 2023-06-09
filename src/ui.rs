use clap::Parser;
use console::Emoji;

/// Struct for handling user input
#[derive(Parser, Debug)]
#[clap(
    author = "Antonio Aguilar",
    version,
    about = "A CLI program to encrypt/decrypt files"
)]
pub struct Cli {
    /// The file to encrypt/decrypt
    pub file: String,

    /// Chooses salting method (only needs to be chosen for encryption)
    /// [OPTIONS = blake3, fib]
    #[arg(short, long, value_parser, default_value = "blake3")]
    pub salt: String,
}

// Emoji macros for convenience
pub static POTATO: Emoji<'_, '_> = Emoji("🥔 ", "");
pub static FLOPPY: Emoji<'_, '_> = Emoji("💾 ", "");
