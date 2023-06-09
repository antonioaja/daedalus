pub const HEADER_AES256_ARGON_FIB: &[u8; 32] = b"DAEDALUSAES256ARGON2FIBONAglowie";
pub const HEADER_AES256_ARGON_BLAKE3: &[u8; 32] = b"DAEDALUSAES256ARGON2BLAKE3glowie";

/// Helper function to find extension (if it exists) of input string
pub fn extension(filename: &str) -> &str {
    filename
        .rfind('.')
        .map(|idx| &filename[idx..])
        .filter(|ext| ext.chars().skip(1).all(|c| c.is_ascii_alphanumeric()))
        .unwrap_or("")
}