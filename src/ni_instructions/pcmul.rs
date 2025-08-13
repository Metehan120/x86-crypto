use core::arch::x86_64::{__m128i, _mm_clmulepi64_si128};

/// PclMul wrapper for ease of use
pub struct PclMul;

unsafe impl Send for PclMul {}

pub trait CarrylessMultiply {
    fn clmul_low(&self, a: __m128i, b: __m128i) -> __m128i;
    fn clmul_high(&self, a: __m128i, b: __m128i) -> __m128i;
    fn clmul_low_high(&self, a: __m128i, b: __m128i) -> __m128i;
    fn clmul_high_low(&self, a: __m128i, b: __m128i) -> __m128i;
    fn clmul_custom<const VALUE: i32>(&self, a: __m128i, b: __m128i) -> __m128i;
}

impl CarrylessMultiply for PclMul {
    #[inline(always)]
    fn clmul_low(&self, a: __m128i, b: __m128i) -> __m128i {
        unsafe { _mm_clmulepi64_si128(a, b, 0x00) }
    }

    #[inline(always)]
    fn clmul_high(&self, a: __m128i, b: __m128i) -> __m128i {
        unsafe { _mm_clmulepi64_si128(a, b, 0x11) }
    }

    #[inline(always)]
    fn clmul_low_high(&self, a: __m128i, b: __m128i) -> __m128i {
        unsafe { _mm_clmulepi64_si128(a, b, 0x01) }
    }

    #[inline(always)]
    fn clmul_high_low(&self, a: __m128i, b: __m128i) -> __m128i {
        unsafe { _mm_clmulepi64_si128(a, b, 0x10) }
    }
    fn clmul_custom<const VALUE: i32>(&self, a: __m128i, b: __m128i) -> __m128i {
        unsafe { _mm_clmulepi64_si128(a, b, VALUE) }
    }
}
