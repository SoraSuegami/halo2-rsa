use num_bigint::BigUint;
pub(crate) fn big_pow_mod(a: &BigUint, b: &BigUint, n: &BigUint) -> BigUint {
    let one = BigUint::from(1usize);
    let two = BigUint::from(2usize);
    if b == &BigUint::default() {
        return one;
    }
    let is_odd = b % &two == one;
    let b = if is_odd { b - &one } else { b.clone() };
    let x = big_pow_mod(a, &(&b / &two), n);
    let x2 = (&x * &x) % n;
    if is_odd {
        (a * &x2) % n
    } else {
        x2
    }
}
