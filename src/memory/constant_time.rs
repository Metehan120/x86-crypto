use core::{arch::x86_64::_mm_sfence, hint::black_box, ptr::read_volatile};

#[inline(always)]
/// Constant-time conditional selection between two u8 values.
///
/// Returns `a` if condition is 1, `b` if condition is 0.
/// Executes in constant time regardless of condition value.
pub fn select_u8(condition: u8, a: u8, b: u8) -> u8 {
    let mask = 0u8.wrapping_sub(condition);
    (a & mask) | (b & !mask)
}

#[inline(always)]
/// Constant-time byte array comparison.
///
/// Returns 1 if arrays are equal, 0 otherwise.
/// Always processes entire arrays to prevent timing attacks.
pub fn compare_bytes(a: &[u8], b: &[u8]) -> u8 {
    if a.len() != b.len() {
        return 0;
    }

    let aptr = a.as_ptr();
    let bptr = b.as_ptr();

    let mut result = 0u8;

    unsafe {
        for i in black_box(0..a.len()) {
            result |= read_volatile(aptr.add(i)) ^ read_volatile(bptr.add(i));
        }

        _mm_sfence();
    }

    (((result as u16).wrapping_sub(1)) >> 8) as u8
}

/// Constant-time conditional clearing of byte array.
///
/// Clears data if condition is 1, leaves unchanged if 0.
/// Always processes entire array for timing safety.
pub fn clear_on_condition(condition: u8, data: &mut [u8]) {
    let mask = condition.wrapping_sub(1);
    for byte in data.iter_mut() {
        *byte &= mask;
    }
}
