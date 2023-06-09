use anyhow::*;
use clap::Parser;
use std::fs::File;
use std::time::*;

use crate::decrypt::decrypt;
use crate::encrypt::encrypt;
use crate::file_format::*;
use crate::legacy::*;
use crate::ui::*;

pub mod decrypt;
pub mod encrypt;
pub mod file_format;
pub mod legacy;
pub mod ui;

fn main() -> Result<()> {
    // Gather input arguments
    let args = Cli::parse();
    if args.salt != "blake3" && args.salt != "fib" {
        println!("Invalid salting method!\n{} is not valid.", args.salt);
        return Ok(());
    }

    // Define time variable
    let now: Instant;

    // Read input file into memory
    let mut file = File::open(&args.file).context(format!("Could not open {}", &args.file))?;

    if extension(&args.file) != ".daedalus" {
        // Request and verify password to encrypt with
        let password = get_password()?;

        // Begin timer
        now = Instant::now();

        // Encrypt the file
        encrypt(&mut file, &args, password)?;
    } else if extension(&args.file) == ".daedalus" {
        // Get password
        let password = rpassword::prompt_password("Password: ")
            .context("Unable to get password from user!")?;

        // Begin timer
        now = Instant::now();

        decrypt(file, args, password)?;
    } else {
        // Begin timer
        now = Instant::now();

        println!("Something went wrong! Invalid extension.\nThis should be impossible. Contact developer.");
    }

    println!("Overall Time Elapsed: {} ms", now.elapsed().as_millis());

    Ok(())
}
