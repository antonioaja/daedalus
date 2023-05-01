# daedalus
daedalus is CLI program which can encrypt/decrypt an input file with a given password. The encryption is done using AES256, with the key being an argon2 hash of the password. A random 16-byte IV is chosen as well.

The output file is a .daedalus file. This includes a 32-byte header, 32-byte blake3 hash of the input, and the 16-byte IV.

## How to Use
daedalus requires two things: input file & password.
Password will be requested without showing plaintext.

For example:

```bash
daedalus secret.txt
```

```bash
Password: <TYPE HERE>
```

The encrypted/decrypted file will be saved in the current working directory.
Encrypted files will be have .daedalus extension.

## Installing
First clone the repo:

```bash
git clone https://github.com/antonioaja/daedalus.git
```

Then change into the directory:

```bash
cd daedalus
```

Finally, install using cargo:

```bash
cargo install --path .
```

## Compiling

Compilation tested using Cargo (1.68).

## Credits

* [libaes](https://github.com/keepsimple1/libaes)
* [anyhow](https://github.com/dtolnay/anyhow)
* [clap](https://github.com/clap-rs/clap)
* [rand](https://github.com/rust-random/rand)
* [argon2](https://github.com/RustCrypto/password-hashes/tree/master/argon2)
* [blake3](https://github.com/BLAKE3-team/BLAKE3)
* [rpassword](https://github.com/conradkleinespel/rpassword)
* [console](https://github.com/console-rs)