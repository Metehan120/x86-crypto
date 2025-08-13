use core::arch::x86_64::{
    __m128i, _mm_sha256msg1_epu32, _mm_sha256msg2_epu32, _mm_sha256rnds2_epu32,
};

#[allow(non_camel_case_types)]
/// SHA-NI Instrcution wrapper for ease of use
///
/// # Example
/// ```rust
/// let shan256_rnds2 = AES_NI.aes_rodun(state, msg, wk);
/// ```
pub struct SHA2_NI;

unsafe impl Send for SHA2_NI {}

pub trait SHA2 {
    fn sha256_rnds2(&self, state: __m128i, msg: __m128i, wk: __m128i) -> __m128i;
    fn sha256_msg1(&self, w0: __m128i, w1: __m128i) -> __m128i;
    fn sha256_msg2(&self, w2: __m128i, w3: __m128i) -> __m128i;
}

impl SHA2 for SHA2_NI {
    #[inline(always)]
    fn sha256_rnds2(&self, state: __m128i, msg: __m128i, wk: __m128i) -> __m128i {
        unsafe { _mm_sha256rnds2_epu32(state, msg, wk) }
    }

    #[inline(always)]
    fn sha256_msg1(&self, w0: __m128i, w1: __m128i) -> __m128i {
        unsafe { _mm_sha256msg1_epu32(w0, w1) }
    }

    #[inline(always)]
    fn sha256_msg2(&self, w2: __m128i, w3: __m128i) -> __m128i {
        unsafe { _mm_sha256msg2_epu32(w2, w3) }
    }
}
