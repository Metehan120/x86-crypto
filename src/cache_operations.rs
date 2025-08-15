use core::{
    arch::x86_64::{_MM_HINT_NTA, _MM_HINT_T0, _MM_HINT_T1, _MM_HINT_T2, _mm_prefetch},
    ops::{Deref, DerefMut},
};

/// Cache prefetch hint levels for performance optimization.
///
/// Specifies which cache level should be targeted for prefetch operations.
/// Different hints optimize for different access patterns and latencies.
pub enum PrefetchHint {
    /// Prefetch to L1 cache (fastest access, smallest capacity)
    L1,
    /// Prefetch to L2 cache (balanced speed/capacity)
    L2,
    /// Prefetch to L3 cache (larger capacity, higher latency)
    L3,
    /// Non-temporal access (bypass cache, for streaming data)
    NTA,
}

#[repr(C, align(64))]
/// Intelligent cache prefetcher for performance optimization.
///
/// Wraps data with automatic cache prefetching to reduce memory latency.
/// Particularly effective for sequential access patterns and large datasets.
pub struct Prefetcher<T> {
    data: T,
    hint: PrefetchHint,
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Prefetcher<T> {
    pub fn new(data: T, hint: PrefetchHint) -> Self {
        Self { data, hint }
    }

    pub fn change_hint(&mut self, hint: PrefetchHint) {
        self.hint = hint;
    }

    #[inline(always)]
    /// Triggers prefetch of wrapped data into specified cache level.
    ///
    /// Prefetches data in 64-byte chunks (typical cache line size)
    /// to minimize cache misses on subsequent accesses.
    pub fn prefetch(&self) {
        for chunk in self.data.as_ref().chunks(64) {
            let ptr = chunk.as_ptr() as *const i8;
            match self.hint {
                PrefetchHint::L1 => unsafe { _mm_prefetch(ptr, _MM_HINT_T0) },
                PrefetchHint::L2 => unsafe { _mm_prefetch(ptr, _MM_HINT_T1) },
                PrefetchHint::L3 => unsafe { _mm_prefetch(ptr, _MM_HINT_T2) },
                PrefetchHint::NTA => unsafe { _mm_prefetch(ptr, _MM_HINT_NTA) },
            }
        }
    }

    #[inline(always)]
    pub fn get(&self) -> &T {
        &self.data
    }

    #[inline(always)]
    pub fn into_inner(self) -> T {
        self.data
    }

    pub fn iter(&self) -> core::slice::Iter<'_, u8> {
        self.prefetch();
        self.data.as_ref().iter()
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.data.as_mut()
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Deref for Prefetcher<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.prefetch();
        &self.data
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> DerefMut for Prefetcher<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.prefetch();
        &mut self.data
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]>> IntoIterator for &'a Prefetcher<T> {
    type Item = &'a u8;
    type IntoIter = core::slice::Iter<'a, u8>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl core::fmt::Debug for PrefetchHint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PrefetchHint::L1 => write!(f, "L1"),
            PrefetchHint::L2 => write!(f, "L2"),
            PrefetchHint::L3 => write!(f, "L3"),
            PrefetchHint::NTA => write!(f, "NTA"),
        }
    }
}

impl<T: core::fmt::Debug + AsRef<[u8]>> core::fmt::Debug for Prefetcher<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Prefetcher")
            .field("data_len", &self.data.as_ref().len())
            .field("hint", &self.hint)
            .finish()
    }
}
