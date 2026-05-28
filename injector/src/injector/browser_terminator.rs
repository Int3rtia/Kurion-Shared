#[allow(dead_code)]
pub struct TerminationOptions {
    pub terminate_children: bool,
    pub wait_for_exit: bool,
}

#[allow(dead_code)]
pub struct TerminationStats {
    pub processes_terminated: usize,
    pub terminated_pids: Vec<u32>,
}

#[allow(dead_code)]
pub struct BrowserTerminator;

#[allow(dead_code)]
impl BrowserTerminator {
    pub fn new() -> Self {
        Self
    }

    pub fn k_by_exe_name(&self, _exe_name: &str, _opts: TerminationOptions) -> TerminationStats {
        TerminationStats {
            processes_terminated: 0,
            terminated_pids: Vec::new(),
        }
    }
}
