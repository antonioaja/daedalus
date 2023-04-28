# daedalus
daedalus is CLI program which can encrypt/decrypt an input file with a given password. The encryption is done using AES256, with the key being a argon2 hash of the password. A random 32-byte IV is chosen as well.

The output file is a .daedalus file.

## How to Use
daedalus requires three things: input file, password, decrypt/encrypt option

For example:

```bash
daedalus -f secret.txt -p password -e
```

The encrypted file will be saved in the current working directory.

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
