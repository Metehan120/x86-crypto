use core::{
    arch::x86_64::{
        __m128, __m128d, __m128i, __m256, __m256d, __m256i, _mm_setzero_si128, _mm_sfence,
        _mm_storeu_si128, _mm256_setzero_si256, _mm256_storeu_si256,
    },
    hint::black_box,
    sync::atomic::{Ordering, compiler_fence},
};

use crate::rng::{CryptoRNG, HWChaCha20Rng, HardwareRandomizable, RngErrors};

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
                zeroize_auto(self)
            }
        })*
    };
}

zeroize! { usize u8 u16 u32 u64 i8 i16 i32 i64 __m128i __m256i __m128 __m256 __m128d __m256d f64 f32 }
randzeroize! { usize u8 u16 u32 u64 i8 i16 i32 i64 }

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
    let mut chacha = HWChaCha20Rng::new(false)?;
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
    let mut chacha = HWChaCha20Rng::new(false).expect("Failed to create ChaCha instance");
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
        compiler_fence(Ordering::SeqCst);
        _mm_sfence();
    }
}

#[deprecated(since = "0.2.0-alpha", note = "Use `sse_zeroize` instead")]
pub fn avx_zeroize() {}

#[target_feature(enable = "sse4.2")]
pub fn sse_zeroize<T>(data: &mut [T]) {
    let elem_size = core::mem::size_of::<T>();
    let chunk_size = 80 / core::mem::size_of::<T>();
    let tail_len = data.len() % chunk_size;
    let main_body_len = data.len() - tail_len;
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
        compiler_fence(Ordering::SeqCst);
        _mm_sfence();
    }
}

#[cfg(feature = "std")]
pub fn zeroize_auto<T>(buf: &mut [T]) {
    if is_x86_feature_detected!("avx2") {
        unsafe { avx2_zeroize(buf) }
    } else if is_x86_feature_detected!("sse4.2") {
        unsafe { sse_zeroize(buf) }
    } else {
        zeroize_func(buf)
    }
}

#[cfg(not(feature = "std"))]
pub fn zeroize_auto<T>(buf: &mut [T]) {
    unsafe { avx2_zeroize(buf) }
}
