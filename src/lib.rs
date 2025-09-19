mod error;
pub mod fs;
mod handler;
mod hooks;
mod procfs;
mod seccomp;

use std::{
    collections::{HashMap, HashSet},
    ops::DerefMut,
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard, OnceLock},
};

pub use error::*;
pub use hooks::*;

use log::{debug, info};
use seccompiler::{SeccompCmpOp, SeccompCondition, SeccompRule, TargetArch};

static GLOBAL: OnceLock<Mutex<Hackcomp>> = OnceLock::new();

pub struct Hackcomp {
    program: seccompiler::BpfProgram,
    syscall_hooks: Vec<Box<dyn SyscallHook>>,
}

impl Hackcomp {
    pub fn get_installed<'a>() -> Option<MutexGuard<'a, Hackcomp>> {
        match GLOBAL.get() {
            None => None,
            Some(m) => m.lock().ok(),
        }
    }

    pub fn install(self) -> crate::Result<()> {
        if GLOBAL.get().is_some() {
            return Err(crate::Error::AlreadyInstalled);
        }

        debug!("PR_SET_NO_NEW_PRIVS 1");
        seccomp::set_no_new_privs()?;

        // Register SIGSYS
        debug!("Registering SIGSYS");
        seccomp::register_sigsys(handler::sigsys_handler as *const u8)?;

        seccompiler::apply_filter_all_threads(&self.program)?;

        // Transfer ownership to static CELL
        GLOBAL
            .set(Mutex::new(self))
            .map_err(|_| crate::Error::AlreadyInstalled)?;

        Ok(())
    }
}

pub struct Builder {
    pc_white_list: (usize, usize),
    syscall_hooks: Vec<Box<dyn SyscallHook>>,
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}

impl Builder {
    pub fn new() -> Self {
        Builder {
            pc_white_list: (0, 0),
            syscall_hooks: Vec::new(),
        }
    }

    pub fn add_hook<H: SyscallHook + 'static>(mut self, hook: H) -> Self {
        self.syscall_hooks.push(Box::new(hook));

        self
    }

    pub fn white_list_self(&mut self) -> crate::Result<()> {
        let ptr = Builder::new as *const u8 as usize;
        debug!("Builder::new is at {ptr}");

        for m in procfs::parse_proc_maps(None)? {
            if m.start_address <= ptr && ptr <= m.end_address {
                debug!("White listing map region {:?}", &m);
                self.pc_white_list = (m.start_address, m.end_address);

                return Ok(());
            }
        }

        Err(crate::Error::Unknown)
    }

    fn white_list_cond1(&self) -> crate::Result<SeccompCondition> {
        let (start, _) = self.pc_white_list;
        Ok(SeccompCondition::new_with_ip(
            SeccompCmpOp::Lt,
            start as u64,
        )?)
    }

    fn white_list_cond2(&self) -> crate::Result<SeccompCondition> {
        let (_, end) = self.pc_white_list;
        Ok(SeccompCondition::new_with_ip(SeccompCmpOp::Gt, end as u64)?)
    }

    pub fn build(mut self) -> crate::Result<Hackcomp> {
        self.white_list_self()?;

        let arch = if cfg!(target_arch = "aarch64") {
            TargetArch::aarch64
        } else if cfg!(target_arch = "x86_64") {
            TargetArch::x86_64
        } else {
            return Err(crate::Error::UnsupportedArch);
        };

        let mut rules: Vec<(i64, Vec<SeccompRule>)> = vec![];

        let keys: HashSet<Sysno> = HashSet::from_iter(
            self.syscall_hooks
                .iter()
                .flat_map(|h| h.hooked_syscalls().iter().cloned()),
        );

        for hook in keys {
            rules.push((
                hook as i64,
                vec![
                    SeccompRule::new(vec![self.white_list_cond1()?])?,
                    SeccompRule::new(vec![self.white_list_cond2()?])?,
                ],
            ));
        }

        let filters = seccompiler::SeccompFilter::new(
            rules.into_iter().collect(),
            // mismatch
            seccompiler::SeccompAction::Allow,
            // match
            seccompiler::SeccompAction::Trap,
            arch,
        )?;

        Ok(Hackcomp {
            syscall_hooks: self.syscall_hooks,
            program: filters.try_into().unwrap(),
        })
    }
}
