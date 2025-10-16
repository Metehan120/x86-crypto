use core::arch::x86_64::{_MM_HINT_T0, _MM_HINT_T1, _mm_prefetch};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::memory::securevec::SecureVec;

/// NEVER USE PREFETCH IN PRODUCTION
pub enum PrefetchMode {
    Off,
    Conservative,
    Aggressive,
}

impl PrefetchMode {
    pub fn perform(&self, data: &[u8]) {
        match self {
            PrefetchMode::Off => (),
            PrefetchMode::Conservative => {
                unsafe { _mm_prefetch(data.as_ptr() as *mut i8, _MM_HINT_T0) };
            }
            PrefetchMode::Aggressive => {
                unsafe { _mm_prefetch(data.as_ptr() as *mut i8, _MM_HINT_T0) };
                unsafe { _mm_prefetch(data.as_ptr() as *mut i8, _MM_HINT_T1) };
            }
        }
    }
}

/// NEVER USE PREFETCH IN PRODUCTION
pub struct Payload<'aad, 'msg> {
    pub msg: &'msg [u8],
    pub prefetch_mode: PrefetchMode,
    pub aad: &'aad [u8],
}

/// NEVER USE PREFETCH IN PRODUCTION
pub struct PayloadMut<'aad, 'msg> {
    pub msg: &'msg mut [u8],
    pub prefetch_mode: PrefetchMode,
    pub aad: &'aad [u8],
}

impl<'aad, 'msg> From<&'msg mut [u8]> for PayloadMut<'aad, 'msg> {
    fn from(msg: &'msg mut [u8]) -> Self {
        Self {
            msg,
            prefetch_mode: PrefetchMode::Off,
            aad: &[],
        }
    }
}

impl<'aad, 'msg, const U: usize> From<&'msg mut [u8; U]> for PayloadMut<'aad, 'msg> {
    fn from(msg: &'msg mut [u8; U]) -> Self {
        Self {
            msg,
            prefetch_mode: PrefetchMode::Off,
            aad: &[],
        }
    }
}

impl<'aad, 'msg> From<&'msg mut Vec<u8>> for PayloadMut<'aad, 'msg> {
    fn from(msg: &'msg mut Vec<u8>) -> Self {
        Self {
            msg,
            prefetch_mode: PrefetchMode::Off,
            aad: &[],
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl<'aad, 'msg> From<&'msg mut SecureVec<u8>> for PayloadMut<'aad, 'msg> {
    fn from(msg: &'msg mut SecureVec<u8>) -> Self {
        Self {
            msg,
            prefetch_mode: PrefetchMode::Off,
            aad: &[],
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl<'aad, 'msg> From<&'msg SecureVec<u8>> for Payload<'aad, 'msg> {
    fn from(msg: &'msg SecureVec<u8>) -> Self {
        Self {
            msg,
            prefetch_mode: PrefetchMode::Off,
            aad: &[],
        }
    }
}

impl<'aad, 'msg> From<&'msg Vec<u8>> for Payload<'aad, 'msg> {
    fn from(msg: &'msg Vec<u8>) -> Self {
        Self {
            msg,
            prefetch_mode: PrefetchMode::Off,
            aad: &[],
        }
    }
}

impl<'aad, 'msg> From<&'msg [u8]> for Payload<'aad, 'msg> {
    fn from(msg: &'msg [u8]) -> Self {
        Self {
            msg,
            prefetch_mode: PrefetchMode::Off,
            aad: &[],
        }
    }
}

impl<'aad, 'msg, const U: usize> From<&'msg [u8; U]> for Payload<'aad, 'msg> {
    fn from(msg: &'msg [u8; U]) -> Self {
        Self {
            msg,
            prefetch_mode: PrefetchMode::Off,
            aad: &[],
        }
    }
}
