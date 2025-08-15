use core::{
    arch::x86_64::{
        __m128i, __m256i, _mm_sha256msg1_epu32, _mm_sha256msg2_epu32, _mm_sha256rnds2_epu32,
        _mm256_sha512msg1_epi64, _mm256_sha512msg2_epi64, _mm256_sha512rnds2_epi64,
    },
    ops::Deref,
};

use crate::types;

#[allow(non_camel_case_types)]
/// SHA-NI Instrcution wrapper for ease of use
///
/// # Example
/// ```rust
/// let shan256_rnds2 = AES_NI.aes_rodun(state, msg, wk);
/// ```
pub struct SHA_NI;

unsafe impl Send for SHA_NI {}

types! {
    type sha_i8: 16 x i8;
    impl deref sha_i8, [i8; 16]

    type sha_i16: 8 x i16;
    impl deref sha_i16, [i16; 8]

    type sha_i32: 4 x i32;
    impl deref sha_i32, [i32; 4]

    type sha_i64: 2 x i64;
    impl deref sha_i64, [i64; 2]
}

types! {
    type sha512_i8: 32 x i8;
    impl deref sha512_i8, [i8; 32]

    type sha512_i16: 16 x i16;
    impl deref sha512_i16, [i16; 16]

    type sha512_i32: 8 x i32;
    impl deref sha512_i32, [i32; 8]

    type sha512_i64: 4 x i64;
    impl deref sha512_i64, [i64; 4]
}

pub trait SHA2 {
    fn sha256_2rounds(&self, state: __m128i, msg: __m128i, wk: __m128i) -> __m128i;
    fn sha256_msg1(&self, w0: __m128i, w1: __m128i) -> __m128i;
    fn sha256_msg2(&self, w2: __m128i, w3: __m128i) -> __m128i;
}

pub trait SHA512 {
    fn sha512_2rounds(&self, state: __m256i, msg: __m256i, wk: __m128i) -> __m256i;
    fn sha512_msg1(&self, w0: __m256i, w1: __m128i) -> __m256i;
    fn sha512_msg2(&self, w2: __m256i, w3: __m256i) -> __m256i;
}

impl SHA512 for SHA_NI {
    fn sha512_2rounds(&self, state: __m256i, msg: __m256i, wk: __m128i) -> __m256i {
        unsafe { _mm256_sha512rnds2_epi64(state, msg, wk) }
    }
    fn sha512_msg1(&self, w0: __m256i, w1: __m128i) -> __m256i {
        unsafe { _mm256_sha512msg1_epi64(w0, w1) }
    }
    fn sha512_msg2(&self, w2: __m256i, w3: __m256i) -> __m256i {
        unsafe { _mm256_sha512msg2_epi64(w2, w3) }
    }
}

impl SHA2 for SHA_NI {
    #[inline(always)]
    fn sha256_2rounds(&self, state: __m128i, msg: __m128i, wk: __m128i) -> __m128i {
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
