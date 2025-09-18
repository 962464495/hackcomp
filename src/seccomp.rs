use log::debug;
use syscalls::{Sysno, syscall};

pub(crate) fn set_no_new_privs() -> crate::Result<()> {
    unsafe {
        syscall!(Sysno::prctl, libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)?;
        Ok(())
    }
}

pub(crate) fn register_sigsys(handler: *const u8) -> crate::Result<()> {
    unsafe {
        let mut sa_mask: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut sa_mask);

        let sa = libc::sigaction {
            sa_sigaction: handler as usize,
            sa_mask,
            sa_flags: libc::SA_SIGINFO,
            sa_restorer: None,
        };

        let sigset_size = std::mem::size_of::<libc::sigset_t>();
        dbg!(sigset_size);

        let r = libc::sigaction(libc::SIGSYS, &sa, std::ptr::null_mut());

        if r == -1 {
            // On error, sigaction returns -1. Get the specific error from errno.
            let err = std::io::Error::last_os_error();
            // Return the error instead of silently continuing
            return Err(err.into());
        }

        debug!("r = {r}");

        // let r = syscall!(
        //     Sysno::rt_sigaction,
        //     libc::SIGSYS,
        //     &sa as *const libc::sigaction,
        //     0,
        //     8
        // )?;
        // dbg!(r);

        Ok(())
    }
}
