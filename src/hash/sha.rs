pub trait ShaFamily<const SIZE: usize> {
    fn new() -> Self;
    fn update(&mut self, buffer: &[u8]);
    fn finalize(&mut self) -> [u8; SIZE];
    fn hash(&mut self, msg: &[u8]) -> [u8; SIZE];
}

#[derive(Debug, Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    offset: usize,
    len_bytes: u64,
}

impl Sha256 {
    fn reset(&mut self) {
        self.state = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        self.buffer = [0u8; 64];
        self.offset = 0;
        self.len_bytes = 0;
    }
}

impl ShaFamily<32> for Sha256 {
    fn new() -> Self {
        let mut s = Sha256 {
            state: [0; 8],
            buffer: [0u8; 64],
            offset: 0,
            len_bytes: 0,
        };
        s.reset();
        s
    }

    fn update(&mut self, mut data: &[u8]) {
        self.len_bytes += data.len() as u64;

        if self.offset != 0 {
            let fill = 64 - self.offset;
            if data.len() >= fill {
                self.buffer[self.offset..].copy_from_slice(&data[..fill]);
                unsafe { sha256_compress_shani(&mut self.state, &self.buffer) };
                self.offset = 0;
                data = &data[fill..];
            } else {
                self.buffer[self.offset..self.offset + data.len()].copy_from_slice(data);
                self.offset += data.len();
                return;
            }
        }

        while data.len() >= 64 {
            let block = <&[u8; 64]>::try_from(&data[..64]).unwrap();
            unsafe { sha256_compress_shani(&mut self.state, block) };
            data = &data[64..];
        }

        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.offset = data.len();
        }
    }

    fn finalize(&mut self) -> [u8; 32] {
        let bit_len = self.len_bytes.wrapping_mul(8);

        self.buffer[self.offset] = 0x80;
        self.offset += 1;

        if self.offset > 56 {
            for b in &mut self.buffer[self.offset..] {
                *b = 0;
            }
            unsafe { sha256_compress_shani(&mut self.state, &self.buffer) };
            self.offset = 0;
        }

        for b in &mut self.buffer[self.offset..56] {
            *b = 0;
        }

        self.buffer[56..].copy_from_slice(&bit_len.to_be_bytes());

        unsafe { sha256_compress_shani(&mut self.state, &self.buffer) };

        let mut out = [0u8; 32];
        for (i, v) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
        }

        self.reset();

        out
    }

    fn hash(&mut self, msg: &[u8]) -> [u8; 32] {
        let mut s = Sha256::new();
        s.update(msg);
        s.finalize()
    }
}

#[allow(unsafe_op_in_unsafe_fn)]
#[inline(always)]
unsafe fn sha256_compress_shani(state: &mut [u32; 8], block: &[u8; 64]) {
    use core::arch::x86_64::*;

    let mut state0: __m128i;
    let mut state1: __m128i;
    let mut msg: __m128i;
    let mut tmp: __m128i;
    let mask: __m128i;
    let mut t0: __m128i;
    let mut t1: __m128i;
    let mut t2: __m128i;
    let mut t3: __m128i;
    let abef_save: __m128i;
    let cdgh_save: __m128i;

    // load state
    tmp = _mm_loadu_si128(state.as_ptr() as *const __m128i);
    state1 = _mm_loadu_si128(state.as_ptr().add(4) as *const __m128i);

    mask = _mm_set_epi64x(0x0c0d0e0f08090a0b_u64 as i64, 0x0405060700010203_u64 as i64);

    tmp = _mm_shuffle_epi32(tmp, 0xB1); // CDAB
    state1 = _mm_shuffle_epi32(state1, 0x1B); // EFGH
    state0 = _mm_alignr_epi8(tmp, state1, 8); // ABEF
    state1 = _mm_blend_epi16(state1, tmp, 0xF0); // CDGH

    let input = block.as_ptr();

    // save initial state
    abef_save = state0;
    cdgh_save = state1;

    // Rounds 0-3
    msg = _mm_loadu_si128(input.add(0) as *const __m128i);
    t0 = _mm_shuffle_epi8(msg, mask);
    msg = _mm_add_epi32(
        t0,
        _mm_set_epi64x(0xE9B5DBA5B5C0FBCF_u64 as i64, 0x71374491428A2F98_u64 as i64),
    );
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

    // Rounds 4-7
    t1 = _mm_loadu_si128(input.add(16) as *const __m128i);
    t1 = _mm_shuffle_epi8(t1, mask);
    msg = _mm_add_epi32(
        t1,
        _mm_set_epi64x(0xAB1C5ED5923F82A4_u64 as i64, 0x59F111F13956C25B_u64 as i64),
    );
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    t0 = _mm_sha256msg1_epu32(t0, t1);

    // Rounds 8-11
    t2 = _mm_loadu_si128(input.add(32) as *const __m128i);
    t2 = _mm_shuffle_epi8(t2, mask);
    msg = _mm_add_epi32(
        t2,
        _mm_set_epi64x(0x550C7DC3243185BE_u64 as i64, 0x12835B01D807AA98_u64 as i64),
    );
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    t1 = _mm_sha256msg1_epu32(t1, t2);

    // Rounds 12-15
    t3 = _mm_loadu_si128(input.add(48) as *const __m128i);
    t3 = _mm_shuffle_epi8(t3, mask);
    msg = _mm_add_epi32(
        t3,
        _mm_set_epi64x(0xC19BF1749BDC06A7_u64 as i64, 0x80DEB1FE72BE5D74_u64 as i64),
    );
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(t3, t2, 4);
    t0 = _mm_add_epi32(t0, tmp);
    t0 = _mm_sha256msg2_epu32(t0, t3);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    t2 = _mm_sha256msg1_epu32(t2, t3);

    // Rounds 16-19
    msg = _mm_add_epi32(
        t0,
        _mm_set_epi64x(0x240CA1CC0FC19DC6_u64 as i64, 0xEFBE4786E49B69C1_u64 as i64),
    );
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(t0, t3, 4);
    t1 = _mm_add_epi32(t1, tmp);
    t1 = _mm_sha256msg2_epu32(t1, t0);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    t3 = _mm_sha256msg1_epu32(t3, t0);

    // Rounds 20-23
    msg = _mm_add_epi32(
        t1,
        _mm_set_epi64x(0x76F988DA5CB0A9DC_u64 as i64, 0x4A7484AA2DE92C6F_u64 as i64),
    );
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(t1, t0, 4);
    t2 = _mm_add_epi32(t2, tmp);
    t2 = _mm_sha256msg2_epu32(t2, t1);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    t0 = _mm_sha256msg1_epu32(t0, t1);

    // Rounds 24-27
    msg = _mm_add_epi32(
        t2,
        _mm_set_epi64x(0xBF597FC7B00327C8_u64 as i64, 0xA831C66D983E5152_u64 as i64),
    );
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(t2, t1, 4);
    t3 = _mm_add_epi32(t3, tmp);
    t3 = _mm_sha256msg2_epu32(t3, t2);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    t1 = _mm_sha256msg1_epu32(t1, t2);

    // Rounds 28-31
    msg = _mm_add_epi32(
        t3,
        _mm_set_epi64x(0x1429296706CA6351_u64 as i64, 0xD5A79147C6E00BF3_u64 as i64),
    );
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(t3, t2, 4);
    t0 = _mm_add_epi32(t0, tmp);
    t0 = _mm_sha256msg2_epu32(t0, t3);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    t2 = _mm_sha256msg1_epu32(t2, t3);

    // Rounds 32-35
    msg = _mm_add_epi32(
        t0,
        _mm_set_epi64x(0x53380D134D2C6DFC_u64 as i64, 0x2E1B213827B70A85_u64 as i64),
    );
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(t0, t3, 4);
    t1 = _mm_add_epi32(t1, tmp);
    t1 = _mm_sha256msg2_epu32(t1, t0);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    t3 = _mm_sha256msg1_epu32(t3, t0);

    // Rounds 36-39
    msg = _mm_add_epi32(
        t1,
        _mm_set_epi64x(0x92722C8581C2C92E_u64 as i64, 0x766A0ABB650A7354_u64 as i64),
    );
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(t1, t0, 4);
    t2 = _mm_add_epi32(t2, tmp);
    t2 = _mm_sha256msg2_epu32(t2, t1);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    t0 = _mm_sha256msg1_epu32(t0, t1);

    // Rounds 40-43
    msg = _mm_add_epi32(
        t2,
        _mm_set_epi64x(0xC76C51A3C24B8B70_u64 as i64, 0xA81A664BA2BFE8A1_u64 as i64),
    );
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(t2, t1, 4);
    t3 = _mm_add_epi32(t3, tmp);
    t3 = _mm_sha256msg2_epu32(t3, t2);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    t1 = _mm_sha256msg1_epu32(t1, t2);

    // Rounds 44-47
    msg = _mm_add_epi32(
        t3,
        _mm_set_epi64x(0x106AA070F40E3585_u64 as i64, 0xD6990624D192E819_u64 as i64),
    );
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(t3, t2, 4);
    t0 = _mm_add_epi32(t0, tmp);
    t0 = _mm_sha256msg2_epu32(t0, t3);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    t2 = _mm_sha256msg1_epu32(t2, t3);

    // Rounds 48-51
    msg = _mm_add_epi32(
        t0,
        _mm_set_epi64x(0x34B0BCB52748774C_u64 as i64, 0x1E376C0819A4C116_u64 as i64),
    );
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(t0, t3, 4);
    t1 = _mm_add_epi32(t1, tmp);
    t1 = _mm_sha256msg2_epu32(t1, t0);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);
    t3 = _mm_sha256msg1_epu32(t3, t0);

    // Rounds 52-55
    msg = _mm_add_epi32(
        t1,
        _mm_set_epi64x(0x682E6FF35B9CCA4F_u64 as i64, 0x4ED8AA4A391C0CB3_u64 as i64),
    );
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(t1, t0, 4);
    t2 = _mm_add_epi32(t2, tmp);
    t2 = _mm_sha256msg2_epu32(t2, t1);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

    // Rounds 56-59
    msg = _mm_add_epi32(
        t2,
        _mm_set_epi64x(0x8CC7020884C87814_u64 as i64, 0x78A5636F748F82EE_u64 as i64),
    );
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    tmp = _mm_alignr_epi8(t2, t1, 4);
    t3 = _mm_add_epi32(t3, tmp);
    t3 = _mm_sha256msg2_epu32(t3, t2);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

    // Rounds 60-63
    msg = _mm_add_epi32(
        t3,
        _mm_set_epi64x(0xC67178F2BEF9A3F7_u64 as i64, 0xA4506CEB90BEFFFA_u64 as i64),
    );
    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
    msg = _mm_shuffle_epi32(msg, 0x0E);
    state0 = _mm_sha256rnds2_epu32(state0, state1, msg);

    // add back to state
    state0 = _mm_add_epi32(state0, abef_save);
    state1 = _mm_add_epi32(state1, cdgh_save);

    // store state back
    tmp = _mm_shuffle_epi32(state0, 0x1B); // FEBA
    state1 = _mm_shuffle_epi32(state1, 0xB1); // DCHG
    state0 = _mm_blend_epi16(tmp, state1, 0xF0); // DCBA
    state1 = _mm_alignr_epi8(state1, tmp, 8); // ABEF

    _mm_storeu_si128(state.as_mut_ptr() as *mut __m128i, state0);
    _mm_storeu_si128(state.as_mut_ptr().add(4) as *mut __m128i, state1);
}
