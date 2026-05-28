use std::cell::Cell;
use std::io::Write;
use crate::version::VERSION;

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[91m";
const GREEN: &str = "\x1b[92m";
const YELLOW: &str = "\x1b[93m";
const BLUE: &str = "\x1b[94m";
const MAGENTA: &str = "\x1b[95m";
const CYAN: &str = "\x1b[96m";
const GRAY: &str = "\x1b[90m";

const UP_ONE: &str = "\x1b[1A";
const CLEAR_LINE: &str = "\x1b[2K";
const CLEAR_BELOW: &str = "\x1b[0J";

pub struct Console {
    verbose: bool,
    section_num: Cell<u8>,
    live_lines: Cell<u16>,
    live: Cell<bool>,
}

impl Console {
    pub fn new(verbose: bool) -> Self {
        Self {
            verbose,
            section_num: Cell::new(0),
            live_lines: Cell::new(0),
            live: Cell::new(false),
        }
    }

    fn track(&self) {
        if self.live.get() {
            self.live_lines.set(self.live_lines.get() + 1);
        }
    }

    fn c_live(&self) {
        let n = self.live_lines.get();
        if n > 0 {
            for _ in 0..n {
                print!("{}{}", UP_ONE, CLEAR_LINE);
            }
            print!("{}", CLEAR_BELOW);
            let _ = std::io::stdout().flush();
        }
        self.live_lines.set(0);
        self.live.set(false);
    }

    fn e_live(&self) {
        self.live_lines.set(0);
        self.live.set(false);
    }

    fn s_show(&self) -> bool {
        self.live.get() || self.verbose
    }

    pub fn banner(&self) {
        println!();
        println!("  {}{}▐{}  {}{}    __ __           _              {}", BOLD, CYAN, RESET, BOLD, CYAN, RESET);
        println!("  {}{}▐{}  {}{}   / //_/_   ______(_)___  ____    {}", BOLD, CYAN, RESET, BOLD, CYAN, RESET);
        println!("  {}{}▐{}  {}{}  / ,< / / / / __ / / __ \\/ __ \\ {}", BOLD, CYAN, RESET, BOLD, CYAN, RESET);
        println!("  {}{}▐{}  {}{} / /| / /_/ / /  / / /_/ / / / /   {}", BOLD, CYAN, RESET, BOLD, CYAN, RESET);
        println!("  {}{}▐{}  {}{}/_/ |_\\__,_/_/  /_/\\____/_/ /_/  {}", BOLD, CYAN, RESET, BOLD, CYAN, RESET);
        println!("  {}{}▐{}", BOLD, CYAN, RESET);
        println!("  {}{}▐{}  {}v{}{}", BOLD, CYAN, RESET, DIM, VERSION, RESET);
        println!();
    }

    pub fn m_header(&self, _title: &str) {
        self.banner();
    }

    pub fn section(&self, name: &str) {
        self.c_live();
        let num = self.section_num.get() + 1;
        self.section_num.set(num);
        println!();
        println!(
            "  {}{}{:02}{}  {}{}{}",
            BOLD, BLUE, num, RESET, BOLD, name, RESET
        );
        println!(
            "  {}──────────────────────────────────────{}",
            GRAY, RESET
        );
    }

    pub fn p_target(&self, target: &str) {
        self.live.set(true);
        self.live_lines.set(0);
        println!("     {}{}· {}...{}", DIM, GRAY, target, RESET);
        self.live_lines.set(1);
    }

    pub fn s_target(&self, target: &str) {
        self.c_live();
        println!("     {}{}✓{}  {}", BOLD, GREEN, RESET, target);
    }

    pub fn f_target(&self, target: &str) {
        self.e_live();
        println!("     {}{}✗  {}{}", DIM, RED, target, RESET);
    }

    pub fn b_header(&self, name: &str, _version: &str) {
        if self.s_show() {
            println!("     {}[{}]{}", GRAY, name, RESET);
            self.track();
        }
    }

    pub fn debug(&self, msg: &str) {
        if self.s_show() {
            println!("     {}INTERIUM DEBUG  {}{}", GRAY, msg, RESET);
            self.track();
        }
    }

    pub fn warn(&self, msg: &str) {
        if self.s_show() {
            println!("     {}!{}  {}{}{}", YELLOW, RESET, DIM, msg, RESET);
            self.track();
        }
    }

    pub fn error(&self, msg: &str) {
        println!("     {}{}✗{}  {}", BOLD, RED, RESET, msg);
        self.track();
    }

    pub fn info(&self, msg: &str) {
        if self.s_show() {
            println!("     {}·{}  {}{}{}", CYAN, RESET, DIM, msg, RESET);
            self.track();
        }
    }

    pub fn l_success(&self, msg: &str) {
        if self.s_show() {
            println!("     {}+{}  {}{}{}", GREEN, RESET, DIM, msg, RESET);
            self.track();
        }
    }

    pub fn success(&self, msg: &str) {
        self.l_success(msg);
    }

    pub fn decryption_key(&self, key: &[u8]) {
        if self.s_show() {
            println!(
                "     {}key{}  {}{}{}",
                MAGENTA, RESET, DIM, hex::encode(key).to_uppercase(), RESET
            );
            self.track();
        }
    }

    pub fn p_stats(
        &self,
        name: &str,
        cookies: usize,
        passwords: usize,
        cards: usize,
        ibans: usize,
    ) {
        if self.s_show() {
            let mut parts = Vec::new();
            if cookies > 0 {
                parts.push(format!("{}c", cookies));
            }
            if passwords > 0 {
                parts.push(format!("{}p", passwords));
            }
            if cards > 0 {
                parts.push(format!("{}cc", cards));
            }
            if ibans > 0 {
                parts.push(format!("{}ib", ibans));
            }
            println!(
                "       {}{} · {}{}",
                GRAY, name, parts.join(" "), RESET
            );
            self.track();
        }
    }

    pub fn summary(
        &self,
        cookies: usize,
        passwords: usize,
        cards: usize,
        ibans: usize,
        tokens: usize,
        profiles: usize,
        path: &str,
    ) {
        if self.s_show() {
            let mut parts = Vec::new();
            if cookies > 0 {
                parts.push(format!("{} cookies", cookies));
            }
            if passwords > 0 {
                parts.push(format!("{} passwords", passwords));
            }
            if cards > 0 {
                parts.push(format!("{} cards", cards));
            }
            if ibans > 0 {
                parts.push(format!("{} IBANs", ibans));
            }
            if tokens > 0 {
                parts.push(format!("{} tokens", tokens));
            }
            if !parts.is_empty() {
                println!(
                    "     {}→{}  {} ({} profile{})",
                    CYAN,
                    RESET,
                    parts.join(", "),
                    profiles,
                    if profiles == 1 { "" } else { "s" }
                );
                println!("       {}{}{}", GRAY, path, RESET);
                if self.live.get() {
                    self.live_lines.set(self.live_lines.get() + 2);
                }
            }
        }
    }

    pub fn l_item(&self, text: &str) {
        println!("     {}·{}  {}", GRAY, RESET, text);
    }

    pub fn s_item(&self, text: &str) {
        println!("       {}└ {}{}", GRAY, text, RESET);
    }

    pub fn separator(&self) {
        println!();
    }
}
