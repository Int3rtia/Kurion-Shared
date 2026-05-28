use std::fs::File;
use std::io::Write;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=KURION_FEATURES");

    let features = std::env::var("KURION_FEATURES").unwrap_or_default();
    if !features.is_empty() {
        println!("cargo:warning=Building payload with features: {}", features);
    }

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("entropy.rs");

    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let mut bytes = [0u8; 64];
    let mut state = seed as u64;
    for b in bytes.iter_mut() {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        *b = (state >> 33) as u8;
    }

    let mut f = File::create(&dest_path).unwrap();
    writeln!(f, "#[used]").unwrap();
    writeln!(f, "#[no_mangle]").unwrap();
    writeln!(f, "pub static BUILD_ENTROPY: [u8; 64] = {:?};", bytes).unwrap();
}
