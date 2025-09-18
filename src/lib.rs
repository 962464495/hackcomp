mod error;
pub mod fs;
mod handler;
mod procfs;
mod seccomp;

use std::{
    collections::HashMap,
    ffi::{CStr, CString},
    path::{Path, PathBuf},
};

pub use error::*;
use log::{debug, info};
use seccompiler::{SeccompCmpOp, SeccompCondition, SeccompRule, TargetArch};

pub trait MappedNode: std::fmt::Debug {
    fn lseek(&mut self, offset: usize, whence: usize) -> usize;
    fn read(&mut self, count: usize) -> Vec<u8>;
}

pub struct Hackcomp {
    program: seccompiler::BpfProgram,
}

impl Hackcomp {
    pub fn install(&self) -> crate::Result<()> {
        debug!("PR_SET_NO_NEW_PRIVS 1");
        seccomp::set_no_new_privs()?;

        // Register SIGSYS
        debug!("Registering SIGSYS");
        seccomp::register_sigsys(handler::sigsys_handler as *const u8)?;

        seccompiler::apply_filter_all_threads(&self.program)?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct Builder {
    pc_white_list: (usize, usize),
    fs_mappings: HashMap<PathBuf, Box<dyn MappedNode>>,
}

impl Builder {
    pub fn new() -> Self {
        Builder {
            pc_white_list: (0, 0),
            fs_mappings: HashMap::new(),
        }
    }

    pub fn add_mapping<P: AsRef<Path>, M: MappedNode + 'static>(&mut self, path: P, node: M) {
        self.fs_mappings
            .insert(path.as_ref().to_owned(), Box::new(node));
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

        dbg!(arch);

        let filters = seccompiler::SeccompFilter::new(
            vec![(
                libc::SYS_openat,
                vec![
                    SeccompRule::new(vec![self.white_list_cond1()?])?,
                    SeccompRule::new(vec![self.white_list_cond2()?])?,
                ],
            )]
            .into_iter()
            .collect(),
            // mismatch
            seccompiler::SeccompAction::Allow,
            // match
            seccompiler::SeccompAction::Trap,
            arch,
        )?;

        Ok(Hackcomp {
            program: filters.try_into().unwrap(),
        })
    }
}
