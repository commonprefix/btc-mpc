fn calculate_f(n: usize) -> usize {
    let mut f = (n - 1) / 3;
    let remainder = (n - 1) % 3;
    if remainder > 0 {
        f += 1;
    }
    f
}

pub fn required_messages(n: usize) -> usize {
    let f = calculate_f(n);
    f + 1
}

pub fn required_confirmations(n: usize) -> usize {
    let f = calculate_f(n);
    2 * f + 1
}
