use bytemuck::Pod;

use crate::memory::{allocator::AllocatorError, securevec::SecureVec};

pub trait SecureVecTransform<T: Sized> {
    fn to_secure_vec(
        &self,
        size: usize,
        madvises: Option<(bool, bool, bool)>,
    ) -> Result<SecureVec<T>, AllocatorError>;
}

impl<T: Sized + Pod> SecureVecTransform<T> for [T] {
    fn to_secure_vec(
        &self,
        size: usize,
        madvises: Option<(bool, bool, bool)>,
    ) -> Result<SecureVec<T>, AllocatorError> {
        let mut vec = SecureVec::with_capacity(size, madvises)?;
        vec.extend_from_slice(self)?;

        Ok(vec)
    }
}
