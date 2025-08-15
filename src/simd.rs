use core::{
    arch::x86_64::*,
    ops::{Add, BitAnd, BitOr, BitXor, Deref, DerefMut, Mul, Sub},
};

macro_rules! impl_avx2 {
    ($($operation_name:ident, $simd_operation:ident),+) => {$(
        #[inline(always)]
        pub fn $operation_name(&self, a: &mut [u8], b: &mut [u8]) {
            for (chunk_a, chunk_b) in a.chunks_exact_mut(32).zip(b.chunks_exact(32)) {
                unsafe {
                    let va = _mm256_loadu_si256(chunk_a.as_ptr() as *const __m256i);
                    let vb = _mm256_loadu_si256(chunk_b.as_ptr() as *const __m256i);
                    let result = $simd_operation(va, vb);
                    _mm256_storeu_si256(chunk_a.as_mut_ptr() as *mut __m256i, result);
                }
            }
        })*
    };

    ($operation_name:ident, $simd_operation:ident, $type:ty) => {
        #[inline(always)]
        pub fn $operation_name(&self, a: &mut [$type], b: &mut [$type]) {
            let chunk_size = 32 / core::mem::size_of::<$type>();
            for (chunk_a, chunk_b) in a.chunks_exact_mut(chunk_size).zip(b.chunks_exact(chunk_size)) {
                unsafe {
                    let va = _mm256_loadu_si256(chunk_a.as_ptr() as *const __m256i);
                    let vb = _mm256_loadu_si256(chunk_b.as_ptr() as *const __m256i);
                    let result = $simd_operation(va, vb);
                    _mm256_storeu_si256(chunk_a.as_mut_ptr() as *mut __m256i, result);
                }
            }
        }
    };
}

/// Bit wise AVX2 Accelerator
///
/// # Examples:
/// ```rust
/// let mut plaintext = [0x43u8; 1024];
/// let key = [0xFFu8; 1024];
///
/// BasicBitAVX2Accelerator.parallel_xor(&mut plaintext, key);
///
/// let mut data = [0xFFu8; 1024];
/// let bitwise = [0x43u8; 1024];
///
/// BasicBitAVX2Accelerator.parallel_or(&mut data, bitwise);
/// BasicBitAVX2Accelerator.parallel_and(&mut data, bitwise);
/// ```
pub struct BasicBitAVX2Accelerator;

impl BasicBitAVX2Accelerator {
    impl_avx2!(
        parallel_xor,
        _mm256_xor_si256,
        parallel_or,
        _mm256_or_si256,
        parallel_and,
        _mm256_and_si256
    );
}

/// Mathematical AVX2 Accelerator
///
/// # Examples:
/// ```rust
/// let mut plaintext = [0x43u8; 1024];
/// let key = [0xFFu8; 1024];
///
/// BasicMathAVX2Accelerator.parallel_add_u8(&mut plaintext, key);
/// BasicBitAVX2Accelerator.parallel_sub_u8(&mut plaintext, key);
/// ```
pub struct BasicMathAVX2Accelerator;

impl BasicMathAVX2Accelerator {
    impl_avx2!(parallel_add_u8, _mm256_add_epi8, u8);
    impl_avx2!(parallel_add_u16, _mm256_add_epi16, u16);
    impl_avx2!(parallel_add_u32, _mm256_add_epi32, u32);
    impl_avx2!(parallel_add_u64, _mm256_add_epi64, u64);
    impl_avx2!(parallel_sub_u8, _mm256_sub_epi8, u8);
    impl_avx2!(parallel_sub_u16, _mm256_sub_epi16, u16);
    impl_avx2!(parallel_sub_u32, _mm256_sub_epi32, u32);
    impl_avx2!(parallel_sub_u64, _mm256_sub_epi64, u64);
    impl_avx2!(parallel_mul_u16, _mm256_mullo_epi16, u16);
    impl_avx2!(parallel_mul_u32, _mm256_mullo_epi32, u32);
    impl_avx2!(parallel_mul_u64, _mm256_mul_epu32, u64);
}

/// A macro wrapper for AVX2 SIMD operations
///
/// Provides a mathematical DSL (Domain Specific Language) for vectorized operations.
/// Automatically dispatches to appropriate AVX2 accelerators based on operation type.
///
/// # Syntax
/// - **Arithmetic**: `simd_operation!(data + other, type)`
/// - **Bitwise**: `simd_operation!(data ^ key)` (defaults to u8)
///
/// # Examples
/// ```rust
/// let mut numbers = vec![1u32; 1024];
/// let addend = vec![2u32; 1024];
///
/// simd_operation!(numbers + addend, u32);  // Parallel addition
/// simd_operation!(data ^ key);             // XOR encryption
/// ```
#[macro_export]
macro_rules! simd_operation {
    ($($data1:tt + $data2:tt, u8)*) => {
        $(BasicMathAVX2Accelerator.parallel_add_u8($data1, $data2))*
    };
    ($($data1:tt + $data2:tt, u16)*) => {
        $(BasicMathAVX2Accelerator.parallel_add_u16($data1, $data2))*
    };
    (($data1:tt + $data2:tt, u32)*) => {
        $(BasicMathAVX2Accelerator.parallel_add_u32($data1, $data2))*
    };
    ($($data1:tt + $data2:tt, u64)*) => {
        $(BasicMathAVX2Accelerator.parallel_add_u64($data1, $data2))*
    };
    ($($data1:tt - $data2:tt, u8)*) => {
        $(BasicMathAVX2Accelerator.parallel_sub_u8($data1, $data2))*
    };
    ($($data1:tt - $data2:tt, u16)*) => {
        $(BasicMathAVX2Accelerator.parallel_sub_u16($data1, $data2))*
    };
    ($($data1:tt - $data2:tt, u32)*) => {
        $(BasicMathAVX2Accelerator.parallel_sub_u32($data1, $data2))*
    };
    ($($data1:tt - $data2:tt, u64)*) => {
        $(BasicMathAVX2Accelerator.parallel_sub_u64($data1, $data2))*
    };
    ($($data1:tt * $data2:tt, u16)*) => {
        $(BasicMathAVX2Accelerator.parallel_mul_u16($data1, $data2))*
    };
    ($($data1:tt * $data2:tt, u32)*) => {
        $(BasicMathAVX2Accelerator.parallel_mul_u32($data1, $data2))*
    };
    ($($data1:tt * $data2:tt, u64)*) => {
        $(BasicMathAVX2Accelerator.parallel_mul_u64($data1, $data2))*
    };
    ($($data1:tt ^ $data2:tt)*) => {
        $(BasicBitAVX2Accelerator.parallel_xor($data1, $data2))*
    };
    ($($data1:tt | $data2:tt)*) => {
        $(BasicBitAVX2Accelerator.parallel_or($data1, $data2))*
    };
    ($($data1:tt & $data2:tt)*) => {
        $(BasicBitAVX2Accelerator.parallel_and($data1, $data2))*
    };
}

unsafe impl Send for BasicBitAVX2Accelerator {}
unsafe impl Sync for BasicBitAVX2Accelerator {}

unsafe impl Send for BasicMathAVX2Accelerator {}
unsafe impl Sync for BasicMathAVX2Accelerator {}

#[derive(Debug, Clone, Copy)]
/// u8 SIMD array support
///
/// **Supported operators**: `+`, `-`, `^`, `&`, `|`
///
/// Can be used like integer type.
///
/// # Examples
/// ```rust
/// let plaintext = SimdU8::load([0x42u8; 1024]);
/// let key = SimdU8::load([0xAAu8; 1024]);
/// let encrypted = plaintext ^ key;
///
/// let data = [0x42u8; 1024]
/// let key_data = [0xAAu8; 1024];
/// let plaintext = SimdU8::load(data);
/// let key = SimdU8::load(key_data);
/// let encrypted = plaintext ^ key;
/// ```
pub struct SimdU8<const U: usize>([u8; U]);
#[derive(Debug, Clone, Copy)]
/// u16 SIMD array support
///
/// **Supported operators**: `+`, `-`, `*`, `^`, `&`, `|`
///
/// Can be used like integer type.
///
/// # Examples
/// ```rust
/// let plaintext = SimdU16::load([0x42u16; 1024]);
/// let key = SimdU16::load([0xAAu16; 1024]);
/// let encrypted = plaintext ^ key;
///
/// let data = [0x42u16; 1024]
/// let key_data = [0xAAu16; 1024];
/// let plaintext = SimdU16::load(data);
/// let key = SimdU16::load(key_data);
/// let encrypted = plaintext ^ key;
/// ```
pub struct SimdU16<const U: usize>([u16; U]);
#[derive(Debug, Clone, Copy)]
/// u32 SIMD array support
///
/// **Supported operators**: `+`, `-`, `*`, `^`, `&`, `|`
///
/// Can be used like integer type.
///
/// # Examples
/// ```rust
/// let plaintext = SimdU32::load([0x42u32; 1024]);
/// let key = SimdU32::load([0xAAu32; 1024]);
/// let encrypted = plaintext ^ key;
///
/// let data = [0x42u32; 1024]
/// let key_data = [0xAAu32; 1024];
/// let plaintext = SimdU32::load(data);
/// let key = SimdU32::load(key_data);
/// let encrypted = plaintext ^ key;
/// ```
pub struct SimdU32<const U: usize>([u32; U]);
#[derive(Debug, Clone, Copy)]
/// u64 SIMD array support
///
/// **Supported operators**: `+`, `-`, `*`, `^`, `&`, `|`
///
/// Can be used like integer type.
///
/// # Examples
/// ```rust
/// let plaintext = SimdU64::load([0x42u64; 1024]);
/// let key = SimdU64::load([0xAAu64; 1024]);
/// let encrypted = plaintext ^ key;
///
/// let data = [0x42u64; 1024]
/// let key_data = [0xAAu64; 1024];
/// let plaintext = SimdU64::load(data);
/// let key = SimdU64::load(key_data);
/// let encrypted = plaintext ^ key;
/// ```
pub struct SimdU64<const U: usize>([u64; U]);

/// SIMD Array load function
///
/// Converts Array to SIMD Array
///
/// # Example
/// ```rust
/// let array = [0u8; 1024];
/// let simd = SimdU8::load(array);
/// ```
pub trait SimdLoadable<T, const U: usize> {
    fn load(data: [T; U]) -> Self;
}

/// SIMD Array store function
///
/// Converts SIMD Array back to Array
///
/// # Examples
/// ```rust
/// let simd_array = SimdU8::load([0u8; 1024]);
/// let array = simd_array.store();
/// ```
pub trait SimdStoreable<T, const U: usize> {
    fn store(&self) -> [T; U];
}

macro_rules! impl_simd {
    ($struct:ident, $inner_type:ty, store) => {
        impl<const U: usize> SimdStoreable<$inner_type, U> for $struct<U> {
            fn store(&self) -> [$inner_type; U] {
                self.0
            }
        }
    };
    ($struct:ident, $inner_type:ty, load) => {
        impl<const U: usize> SimdLoadable<$inner_type, U> for $struct<U> {
            fn load(data: [$inner_type; U]) -> Self {
                $struct(data)
            }
        }
    };
    ($struct:ident, $inner_type:ty, deref) => {
        impl<const U: usize> Deref for $struct<U> {
            type Target = [$inner_type; U];

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl<const U: usize> DerefMut for $struct<U> {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }
    };
    ($($struct:ident, $inner_type:ty),+) => {$(
        impl_simd!($struct, $inner_type, store);
        impl_simd!($struct, $inner_type, load);
        impl_simd!($struct, $inner_type, deref);
    )*};
}

impl_simd!(SimdU8, u8, SimdU16, u16, SimdU32, u32, SimdU64, u64);

macro_rules! impl_math {
    ($struct:ident, $op:tt, $op_name:tt, add) => {
        impl<const U: usize> Add for $struct<U> {
            type Output = $struct<U>;

            fn add(mut self, mut rhs: Self) -> Self::Output {
                $op.$op_name(&mut self.0, &mut rhs.0);
                self
            }
        }
    };

    ($struct:ident, $op:ident, $op_name:tt, sub) => {
        impl<const U: usize> Sub for $struct<U> {
            type Output = $struct<U>;

            fn sub(mut self, mut rhs: Self) -> Self::Output {
                $op.$op_name(&mut self.0, &mut rhs.0);
                self
            }
        }
    };

    ($struct:ident, $op:ident, $op_name:tt, mul) => {
        impl<const U: usize> Mul for $struct<U> {
            type Output = $struct<U>;

            fn mul(mut self, mut rhs: Self) -> Self::Output {
                $op.$op_name(&mut self.0, &mut rhs.0);
                self
            }
        }
    };
}

impl_math!(SimdU8, BasicMathAVX2Accelerator, parallel_add_u8, add);
impl_math!(SimdU16, BasicMathAVX2Accelerator, parallel_add_u16, add);
impl_math!(SimdU32, BasicMathAVX2Accelerator, parallel_add_u32, add);
impl_math!(SimdU64, BasicMathAVX2Accelerator, parallel_add_u64, add);
impl_math!(SimdU8, BasicMathAVX2Accelerator, parallel_sub_u8, sub);
impl_math!(SimdU16, BasicMathAVX2Accelerator, parallel_sub_u16, sub);
impl_math!(SimdU32, BasicMathAVX2Accelerator, parallel_sub_u32, sub);
impl_math!(SimdU64, BasicMathAVX2Accelerator, parallel_sub_u64, sub);
impl_math!(SimdU16, BasicMathAVX2Accelerator, parallel_mul_u16, mul);
impl_math!(SimdU32, BasicMathAVX2Accelerator, parallel_mul_u32, mul);
impl_math!(SimdU64, BasicMathAVX2Accelerator, parallel_mul_u64, mul);

impl<const U: usize> BitXor for SimdU8<U> {
    type Output = SimdU8<U>;

    fn bitxor(mut self, mut rhs: Self) -> Self::Output {
        BasicBitAVX2Accelerator.parallel_xor(&mut self.0, &mut rhs.0);
        self
    }
}

impl<const U: usize> BitAnd for SimdU8<U> {
    type Output = SimdU8<U>;

    fn bitand(mut self, mut rhs: Self) -> Self::Output {
        BasicBitAVX2Accelerator.parallel_and(&mut self.0, &mut rhs.0);
        self
    }
}

impl<const U: usize> BitOr for SimdU8<U> {
    type Output = SimdU8<U>;

    fn bitor(mut self, mut rhs: Self) -> Self::Output {
        BasicBitAVX2Accelerator.parallel_or(&mut self.0, &mut rhs.0);
        self
    }
}

macro_rules! impl_from {
    ($type:ty, $class:ident, $size:expr) => {
        impl From<&[$type]> for $class<$size> {
            fn from(slice: &[$type]) -> Self {
                let mut data = [0 as $type; $size];
                let len = slice.len().min($size);
                data[..len].copy_from_slice(&slice[..len]);
                Self::load(data)
            }
        }
    };
}

impl_from!(u8, SimdU8, 32);
impl_from!(u8, SimdU8, 64);
impl_from!(u16, SimdU16, 16);
impl_from!(u16, SimdU16, 32);
impl_from!(u32, SimdU32, 8);
impl_from!(u32, SimdU32, 16);
impl_from!(u64, SimdU64, 4);
impl_from!(u64, SimdU64, 8);

#[allow(non_camel_case_types)]
/// 32 byte u8 type for SIMD
pub type u8x32 = SimdU8<32>;

#[allow(non_camel_case_types)]
/// 64 byte u8 type for SIMD
pub type u8x64 = SimdU8<64>;

#[allow(non_camel_case_types)]
/// 16 byte u16 type for SIMD
pub type u16x16 = SimdU16<16>;

#[allow(non_camel_case_types)]
/// 32 byte u16 type for SIMD
pub type u16x32 = SimdU16<32>;

#[allow(non_camel_case_types)]
/// 8 byte u32 type for SIMD
pub type u32x8 = SimdU32<8>;

#[allow(non_camel_case_types)]
/// 16 byte u32 type for SIMD
pub type u32x16 = SimdU32<16>;

#[allow(non_camel_case_types)]
/// 4 byte u64 type for SIMD
pub type u64x4 = SimdU64<4>;

#[allow(non_camel_case_types)]
/// 8 byte u64 type for SIMD
pub type u64x8 = SimdU64<8>;
