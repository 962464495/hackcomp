mod error;
pub mod fs;
mod handler;
mod hooks;
pub mod procfs;
mod seccomp;

// JNI 接口模块（用于 LSPosed 集成）
#[cfg(target_os = "android")]
pub mod jni;

use std::collections::{BTreeMap, HashSet};

pub use error::*;
pub use hooks::*;

use seccompiler::TargetArch;
pub use seccompiler::{SeccompCmpOp, SeccompCondition, SeccompRule};

use log::{debug, info};

static GLOBAL: spin::Once<spin::Mutex<Hackcomp>> = spin::Once::new();

pub struct Hackcomp {
    program: seccompiler::BpfProgram,
    syscall_hooks: Vec<Box<dyn SyscallHook>>,
}

impl Hackcomp {
    pub fn get_installed<'a>() -> Option<spin::MutexGuard<'a, Hackcomp>> {
        GLOBAL.get().map(|f| f.lock())
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
        GLOBAL.call_once(|| spin::Mutex::new(self));

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
        info!("Building hackcomp with {} hooks", self.syscall_hooks.len());
        self.white_list_self()?;

        let arch = if cfg!(target_arch = "aarch64") {
            TargetArch::aarch64
        } else if cfg!(target_arch = "x86_64") {
            TargetArch::x86_64
        } else {
            return Err(crate::Error::UnsupportedArch);
        };

        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

        // let keys: HashSet<Sysno> = HashSet::from_iter(
        //     self.syscall_hooks
        //         .iter()
        //         .flat_map(|h| h.hooked_syscalls().iter().cloned()),
        // );

        for hook in &self.syscall_hooks {
            for sysno in hook.hooked_syscalls() {
                let mut custom_rules = hook.bpf_rules(*sysno);

                if custom_rules.is_empty() {
                    custom_rules.push(vec![]);
                }

                for r in custom_rules.drain(..) {
                    let mut cond1 = vec![self.white_list_cond1()?];
                    cond1.extend(r.iter().cloned());
                    let mut cond2 = vec![self.white_list_cond2()?];
                    cond2.extend(r.into_iter());

                    if let Some(v) = rules.get_mut(&(*sysno as i64)) {
                        v.push(SeccompRule::new(cond1)?);
                        v.push(SeccompRule::new(cond2)?);
                    } else {
                        rules.insert(
                            *sysno as i64,
                            vec![SeccompRule::new(cond1)?, SeccompRule::new(cond2)?],
                        );
                    }
                }
            }
        }

        let filters = seccompiler::SeccompFilter::new(
            rules,
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
