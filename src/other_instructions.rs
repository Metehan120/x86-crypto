use core::arch::{
    asm,
    x86_64::{_mm_crc32_u8, _mm_crc32_u16, _mm_crc32_u32, _mm_crc32_u64},
};

use macros::stable_api;

#[stable_api(since = "0.1.0")]
/// Hardware-accelerated CRC32 checksum computation using SSE4.2 instructions.
///
/// Provides direct access to x86 CRC32 instructions for high-performance
/// cyclic redundancy check calculations. Uses the Castagnoli polynomial
/// (0x1EDC6F41) which is optimized for error detection in network protocols.
///
/// # Performance
/// - ~1-4 cycles per operation (hardware accelerated)
/// - Significantly faster than software implementations
/// - Suitable for high-throughput data integrity verification
///
/// # Use Cases
/// - Network packet checksums
/// - File integrity verification
/// - Data corruption detection
/// - iSCSI, SCTP protocol implementations
///
/// # Example
/// ```rust
/// let crc = CRC32;
/// let mut checksum = 0;
///
/// // Process data incrementally
/// checksum = crc.crc32_u8(checksum, 0x42);
/// checksum = crc.crc32_u32(checksum, 0xDEADBEEF);
///
/// println!("Final CRC32: 0x{:08X}", checksum);
/// ```
///
/// # Note
/// Requires SSE4.2 support. Check with `is_x86_feature_detected!("sse4.2")`.
pub struct CRC32;

impl CRC32 {
    #[inline(always)]
    pub fn u8(&self, a: u32, b: u8) -> u32 {
        unsafe { _mm_crc32_u8(a, b) }
    }

    #[inline(always)]
    pub fn u16(&self, a: u32, b: u16) -> u32 {
        unsafe { _mm_crc32_u16(a, b) }
    }

    #[inline(always)]
    pub fn u32(&self, a: u32, b: u32) -> u32 {
        unsafe { _mm_crc32_u32(a, b) }
    }

    #[inline(always)]
    pub fn u64(&self, a: u64, b: u64) -> u64 {
        unsafe { _mm_crc32_u64(a, b) }
    }
}

/// Intel BMI1 (Bit Manipulation Instruction Set 1) hardware operations.
///
/// Provides direct access to BMI1 instructions for efficient bit manipulation
/// operations. These instructions are optimized for cryptographic algorithms,
/// compression, and high-performance computing applications.
///
/// # Supported Instructions
/// - `PDEP`: Parallel bits deposit using mask
/// - `PEXT`: Parallel bits extract using mask
/// - `BLSI`: Extract lowest set isolated bit
/// - `BLSR`: Reset lowest set bit
///
/// # Performance
/// - Single-cycle execution on modern processors
/// - Replaces complex bit manipulation sequences
/// - Essential for efficient cryptographic implementations
///
/// # Use Cases
/// - Bit permutations in block ciphers
/// - Sparse matrix operations
/// - Compression algorithms
/// - Hash function optimizations
///
/// # Example
/// ```rust
/// // Extract bits using mask
/// let data = 0b11010110u32;
/// let mask = 0b11110000u32;
/// let extracted = unsafe { BMI1::pext_u32(data, mask) };
///
/// // Deposit bits back
/// let deposited = unsafe { BMI1::pdep_u32(extracted, mask) };
/// ```
///
/// # Safety
/// All methods are `unsafe` as they use inline assembly. Requires BMI1
/// CPU support (Intel Haswell+, AMD Piledriver+).
pub struct BMI1;

impl BMI1 {
    #[inline(always)]
    pub unsafe fn pdep_u32(&self, src: u32, mask: u32) -> u32 {
        let result: u32;
        unsafe { asm!("pdep {0:e}, {1:e}, {2:e}", out(reg) result, in(reg) src, in(reg) mask) };
        result
    }

    #[inline(always)]
    pub unsafe fn pdep_u64(&self, src: u64, mask: u64) -> u64 {
        let result: u64;
        unsafe { asm!("pdep {}, {}, {}", out(reg) result, in(reg) src, in(reg) mask) };
        result
    }

    #[inline(always)]
    pub unsafe fn pext_u32(&self, src: u32, mask: u32) -> u32 {
        let result: u32;
        unsafe { asm!("pext {0:e}, {1:e}, {2:e}", out(reg) result, in(reg) src, in(reg) mask) };
        result
    }

    #[inline(always)]
    pub unsafe fn pext_u64(&self, src: u64, mask: u64) -> u64 {
        let result: u64;
        unsafe { asm!("pext {}, {}, {}", out(reg) result, in(reg) src, in(reg) mask) };
        result
    }

    #[inline(always)]
    pub unsafe fn blsi_u32(&self, src: u32) -> u32 {
        let result: u32;
        unsafe { asm!("blsi {0:e}, {1:e}", out(reg) result, in(reg) src) };
        result
    }

    #[inline(always)]
    pub unsafe fn blsi_u64(&self, src: u64) -> u64 {
        let result: u64;
        unsafe { asm!("blsi {}, {}", out(reg) result, in(reg) src) };
        result
    }

    #[inline(always)]
    pub unsafe fn blsr_u32(&self, src: u32) -> u32 {
        let result: u32;
        unsafe { asm!("blsr {0:e}, {1:e}", out(reg) result, in(reg) src) };
        result
    }

    #[inline(always)]
    pub unsafe fn blsr_u64(&self, src: u64) -> u64 {
        let result: u64;
        unsafe { asm!("blsr {}, {}", out(reg) result, in(reg) src) };
        result
    }
}

/// Intel BMI2 (Bit Manipulation Instruction Set 2) hardware operations.
///
/// Provides direct access to BMI2 instructions for advanced bit manipulation
/// and variable shift operations. These instructions complement BMI1 with
/// additional bit-level operations optimized for modern algorithms.
///
/// # Supported Instructions
/// - `BZHI`: Zero high bits starting from specified index
/// - `RORX`: Rotate right without affecting flags (immediate)
///
/// # Performance
/// - Single-cycle execution on supported processors
/// - Flag-preserving operations for better instruction scheduling
/// - Eliminates need for complex masking sequences
///
/// # Use Cases
/// - Bit field extraction and manipulation
/// - Cryptographic bit rotations
/// - Fast division by powers of 2
/// - Compiler optimizations for bit operations
///
/// # Example
/// ```rust
/// // Zero high bits from index 8
/// let data = 0xFFFFFFFFu32;
/// let result = unsafe { BMI2::bzhi_u32(data, 8) }; // 0x000000FF
///
/// // Rotate right by 8 positions
/// let rotated = unsafe { BMI2::rorx_u32::<8>(0x12345678) }; // 0x78123456
/// ```
///
/// # Safety
/// All methods are `unsafe` as they use inline assembly. Requires BMI2
/// CPU support (Intel Haswell+, AMD Excavator+).
pub struct BMI2;

impl BMI2 {
    #[inline(always)]
    pub unsafe fn bzhi_u32(&self, src: u32, index: u32) -> u32 {
        let result: u32;
        unsafe { asm!("bzhi {0:e}, {1:e}, {2:e}", out(reg) result, in(reg) src, in(reg) index) };
        result
    }

    #[inline(always)]
    pub unsafe fn bzhi_u64(&self, src: u64, index: u64) -> u64 {
        let result: u64;
        unsafe { asm!("bzhi {}, {}, {}", out(reg) result, in(reg) src, in(reg) index) };
        result
    }

    #[inline(always)]
    pub unsafe fn rorx_u32<const IMM: u8>(&self, src: u32) -> u32 {
        let result: u32;
        unsafe { asm!("rorx {0:e}, {1:e}, {2}", out(reg) result, in(reg) src, const IMM) };
        result
    }

    #[inline(always)]
    pub unsafe fn rorx_u64<const IMM: u8>(&self, src: u64) -> u64 {
        let result: u64;
        unsafe { asm!("rorx {}, {}, {}", out(reg) result, in(reg) src, const IMM) };
        result
    }
}
