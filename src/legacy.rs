/// Creates a 'salt' from the length of the password using the fibonacci sequence
/// Better than nothing, but no longer used for security reasons
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
        out_salt += "0";
    }

    out_salt
}