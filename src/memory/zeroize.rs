use core::{
    arch::x86_64::{
        __m128, __m128d, __m128i, __m256, __m256d, __m256i, _mm_setzero_si128, _mm_sfence,
        _mm_storeu_si128, _mm256_setzero_si256, _mm256_storeu_si256,
    },
    hint::black_box,
    sync::atomic::{Ordering, compiler_fence},
};

use crate::{
    CryptoRNG, RngErrors,
    ni_instructions::{
        aesni::{__rsi128keys, __rsi192keys, __rsi256keys, __rsi512keys},
        vaes::{__vaes256i, __vaes256key, __vaes256keys, __vaes512keys},
    },
    rng::{HWChaCha20Rng, HardwareRandomizable},
};

/// Random-fill-then-zero memory clearing trait.
///
/// Overwrites memory with random data before zeroing to resist
/// forensic recovery and cold boot attacks.
pub trait RandZeroizeable {
    fn rand_zeroize(&mut self) -> Result<(), RngErrors>;
    fn rand_zeroize_unchecked(&mut self) -> ();
}

macro_rules! randzeroize {
    ($($type:ty)*) => {
        $(impl RandZeroizeable for [$type] {
            #[inline(always)]
            fn rand_zeroize(&mut self) -> Result<(), RngErrors> {
                rand_zeroize_func(self)
            }
            fn rand_zeroize_unchecked(&mut self) {
                rand_zeroize_unchecked_func(self)
            }
        })*
    };
}

pub trait Zeroizeable {
    fn zeroize(&mut self);
}

macro_rules! zeroize {
    ($($type:ty)*) => {
        $(impl Zeroizeable for [$type] {
            fn zeroize(&mut self) {
                zeroize_func(self)
            }
        })*
    };
}

pub trait SimdZeroize {
    fn par_zeroize(&mut self);
    fn avx_par_zeroize(&mut self);
}

macro_rules! simdzeroize {
    ($($type:ty)*) => {
        $(impl SimdZeroize for [$type] {
            fn par_zeroize(&mut self) {
                unsafe { avx2_zeroize(self) }
            }
            fn avx_par_zeroize(&mut self) {
                unsafe { avx_zeroize(self) }
            }
        })*
    };
}

zeroize! { usize u8 u16 u32 u64 i8 i16 i32 i64 __m128i __m256i __m128 __m256 __m128d __m256d __vaes256i __vaes256key __vaes256keys __vaes512keys __rsi128keys __rsi192keys __rsi256keys __rsi512keys f64 f32 }
randzeroize! { usize u8 u16 u32 u64 i8 i16 i32 i64 }
simdzeroize! { usize u8 u16 u32 u64 i8 i16 i32 i64 __m128i __m256i __m128 __m256 __m128d __m256d __vaes256i __vaes256key __vaes256keys __vaes512keys __rsi128keys __rsi192keys __rsi256keys __rsi512keys f64 f32 }

#[inline(never)]
pub fn zeroize_func<T>(data: &mut [T]) {
    unsafe {
        let ptr = data.as_mut_ptr();
        for i in black_box(0..data.len()) {
            core::ptr::write_volatile(ptr.add(i), core::mem::zeroed());
        }
        compiler_fence(Ordering::SeqCst);
        _mm_sfence();
    }
}

#[inline(never)]
pub fn rand_zeroize_func<T: HardwareRandomizable>(data: &mut [T]) -> Result<(), RngErrors> {
    let mut chacha = HWChaCha20Rng::new()?;
    chacha.fill_by_unchecked(data);

    unsafe {
        let ptr = data.as_mut_ptr();
        for i in black_box(0..data.len()) {
            core::ptr::write_volatile(ptr.add(i), core::mem::zeroed());
        }
        compiler_fence(Ordering::SeqCst);
        _mm_sfence();
    }

    Ok(())
}

#[inline(never)]
pub fn rand_zeroize_unchecked_func<T: HardwareRandomizable>(data: &mut [T]) {
    let mut chacha = HWChaCha20Rng::new().expect("Failed to create ChaCha instance");
    chacha.fill_by_unchecked(data);

    unsafe {
        let ptr = data.as_mut_ptr();
        for i in black_box(0..data.len()) {
            core::ptr::write_volatile(ptr.add(i), core::mem::zeroed());
        }
        compiler_fence(Ordering::SeqCst);
        _mm_sfence();
    }
}

fn volatile_touch<T>(data: &mut [T]) {
    let ptr = data.as_mut_ptr();
    if !data.is_empty() {
        for i in black_box(0..data.len()) {
            unsafe { core::ptr::write_volatile(ptr.add(i), core::mem::zeroed()) };
        }
    }
}

#[target_feature(enable = "avx2")]
pub fn avx2_zeroize<T>(data: &mut [T]) {
    let elem_size = core::mem::size_of::<T>();
    let chunk_size = 160 / core::mem::size_of::<T>();
    let tail_len = data.len() % chunk_size;
    let main_body_len = data.len() - tail_len;
    assert!(160 % elem_size == 0, "T must divide 160 bytes evenly");
    let stride = 32 / elem_size;

    let (main_body, tail) = data.split_at_mut(main_body_len);

    unsafe {
        for chunk in black_box(main_body.chunks_exact_mut(chunk_size)) {
            _mm256_storeu_si256(chunk.as_mut_ptr() as *mut __m256i, _mm256_setzero_si256());
            _mm256_storeu_si256(
                chunk.as_mut_ptr().add(stride * 1) as *mut __m256i,
                _mm256_setzero_si256(),
            );
            _mm256_storeu_si256(
                chunk.as_mut_ptr().add(stride * 2) as *mut __m256i,
                _mm256_setzero_si256(),
            );
            _mm256_storeu_si256(
                chunk.as_mut_ptr().add(stride * 3) as *mut __m256i,
                _mm256_setzero_si256(),
            );
            _mm256_storeu_si256(
                chunk.as_mut_ptr().add(stride * 4) as *mut __m256i,
                _mm256_setzero_si256(),
            );
        }

        volatile_touch(tail);
        _mm_sfence();
    }
}

#[target_feature(enable = "avx")]
pub fn avx_zeroize<T>(data: &mut [T]) {
    let elem_size = core::mem::size_of::<T>();
    let chunk_size = 80 / core::mem::size_of::<T>();
    let tail_len = data.len() % chunk_size;
    let main_body_len = data.len() - tail_len;
    assert!(80 % elem_size == 0, "T must divide 80 bytes evenly");
    let stride = 16 / elem_size;

    let (main_body, tail) = data.split_at_mut(main_body_len);

    unsafe {
        for chunk in black_box(main_body.chunks_exact_mut(chunk_size)) {
            _mm_storeu_si128(chunk.as_mut_ptr() as *mut __m128i, _mm_setzero_si128());
            _mm_storeu_si128(
                chunk.as_mut_ptr().add(stride * 1) as *mut __m128i,
                _mm_setzero_si128(),
            );
            _mm_storeu_si128(
                chunk.as_mut_ptr().add(stride * 2) as *mut __m128i,
                _mm_setzero_si128(),
            );
            _mm_storeu_si128(
                chunk.as_mut_ptr().add(stride * 3) as *mut __m128i,
                _mm_setzero_si128(),
            );
            _mm_storeu_si128(
                chunk.as_mut_ptr().add(stride * 4) as *mut __m128i,
                _mm_setzero_si128(),
            );
        }

        volatile_touch(tail);
        _mm_sfence();
    }
}
