use core::mem::MaybeUninit;

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "wabrix_umem")]
unsafe extern "C" {
    fn load8(offset: u32) -> u32;
    fn load64(offset: u32) -> u64;
    fn store8(offset: u32, value: u32);
    fn store64(offset: u32, value: u64);
}

#[inline(always)]
pub(crate) unsafe fn read<T: Copy>(offset: u32) -> T {
    let mut value = MaybeUninit::<T>::uninit();
    let dst = value.as_mut_ptr() as *mut u8;
    #[cfg(target_arch = "wasm32")]
    unsafe {
        let mut pos = 0;
        while pos + 8 <= core::mem::size_of::<T>() {
            (dst.add(pos) as *mut u64).write_unaligned(load64(offset + pos as u32));
            pos += 8;
        }
        while pos < core::mem::size_of::<T>() {
            dst.add(pos).write(load8(offset + pos as u32) as u8);
            pos += 1;
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    unsafe {
        core::ptr::copy_nonoverlapping(offset as usize as *const u8, dst, core::mem::size_of::<T>())
    }
    unsafe { value.assume_init() }
}

#[inline(always)]
pub(crate) unsafe fn write<T: Copy>(offset: u32, value: &T) {
    unsafe {
        copy_to(
            offset,
            value as *const T as *const u8,
            core::mem::size_of::<T>(),
        )
    }
}

#[inline(always)]
pub(crate) unsafe fn copy_to(offset: u32, src: *const u8, len: usize) {
    #[cfg(target_arch = "wasm32")]
    unsafe {
        let mut pos = 0;
        while pos + 8 <= len {
            store64(
                offset + pos as u32,
                (src.add(pos) as *const u64).read_unaligned(),
            );
            pos += 8;
        }
        while pos < len {
            store8(offset + pos as u32, *src.add(pos) as u32);
            pos += 1;
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    unsafe {
        core::ptr::copy_nonoverlapping(src, offset as usize as *mut u8, len)
    }
}

#[inline(always)]
pub(crate) unsafe fn copy_from(dst: *mut u8, offset: u32, len: usize) {
    let mut pos = 0;
    while pos < len {
        unsafe { *dst.add(pos) = read::<u8>(offset + pos as u32) };
        pos += 1;
    }
}
