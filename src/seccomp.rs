pub(crate) fn set_no_new_privs() -> crate::Result<()> {
    unsafe {
        nc::prctl(nc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)?;
        Ok(())
    }
}

pub type HandlerFunc = unsafe extern "C" fn(i32, *mut ndk_sys::siginfo, *mut core::ffi::c_void);

pub(crate) fn register_sigsys(handler: *const u8) -> crate::Result<()> {
    unsafe {
        let mut sa_mask: ndk_sys::sigset_t = std::mem::zeroed();
        ndk_sys::sigemptyset(&mut sa_mask);

        let handler: HandlerFunc = std::mem::transmute(handler);

        let sa = ndk_sys::sigaction {
            __bindgen_anon_1: ndk_sys::sigaction__bindgen_ty_1 {
                sa_sigaction: Some(handler),
            },
            sa_mask,
            sa_flags: ndk_sys::SA_SIGINFO as i32,
            sa_restorer: None,
        };

        let r = ndk_sys::sigaction(nc::SIGSYS, &sa, std::ptr::null_mut());

        if r == -1 {
            // On error, sigaction returns -1. Get the specific error from errno.
            let err = std::io::Error::last_os_error();
            // Return the error instead of silently continuing
            return Err(err.into());
        }

        Ok(())
    }
}
