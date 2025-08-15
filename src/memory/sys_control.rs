#[cfg(target_os = "linux")]
pub fn disable_dump() -> u8 {
    use libc::{PR_SET_DUMPABLE, prctl};
    use log::error;

    if (unsafe { prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) }) != 0 {
        error!(
            "Failed to disable dumpable: {}",
            std::io::Error::last_os_error()
        );
        0
    } else {
        1
    }
}

#[cfg(target_os = "linux")]
pub fn disable_ptrace() -> u8 {
    use libc::{PR_SET_DUMPABLE, PR_SET_PTRACER, prctl};
    use log::{error, info};
    use std::io;

    let r1 = unsafe { prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) };

    let r2 = unsafe { prctl(PR_SET_PTRACER, 0, 0, 0, 0) };

    if r1 != 0 || r2 != 0 {
        error!(
            "Failed to harden against ptrace: {}",
            io::Error::last_os_error()
        );
        0
    } else {
        info!("Ptrace effectively disabled (dumpable=0, no future tracer)");
        1
    }
}

#[cfg(target_os = "linux")]
pub fn lock_all_memory() -> u8 {
    use libc::{MCL_CURRENT, MCL_FUTURE, mlockall};
    use log::{error, info};
    use std::io;

    if unsafe { mlockall(MCL_CURRENT | MCL_FUTURE) } != 0 {
        error!("mlockall failed: {}", io::Error::last_os_error());
        0
    } else {
        info!("Process memory locked into RAM");
        1
    }
}

#[cfg(target_os = "linux")]
pub fn unlock_all_memory() -> u8 {
    use libc::munlockall;
    use log::{error, info};
    use std::io;

    if (unsafe { munlockall() }) != 0 {
        error!("munlockall failed: {}", io::Error::last_os_error());
        0
    } else {
        info!("Process memory unlocked from RAM");
        1
    }
}
