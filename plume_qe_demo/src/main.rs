use anyhow::{Context, Result, bail};
use blake3::Hasher;
use clap::{Parser, Subcommand, ValueEnum};
use env_logger::Env;
use hex::{FromHex, encode as hex_encode};
use hostname::get as get_hostname;
use log::{LevelFilter, debug};
use plume_qe_core::{
    ChaoticScheduler, Ciphertext, EncryptedPayload, KemCiphertext, PayloadOptions, PayloadView,
    PolyKeyPair, PolymorphismEngine, PolymorphismIntensity, SchedulerParams, SecurityLevel,
    SecurityPreset, decapsulate, decrypt, decrypt_payload_view, encapsulate, encrypt,
    encrypt_payload, keygen_bundle, mix_seed_with_fingerprint, security_preset,
};
use rand::rngs::OsRng;
use serde::de::DeserializeOwned;
use serde_json;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "plume-qe",
    author,
    version,
    about = "PLUME-QE Phase 3 CLI (experimental)"
)]
struct Cli {
    #[arg(long, global = true)]
    debug: bool,
    #[arg(long, global = true)]
    context: Option<String>,
    #[arg(long, global = true, value_enum, default_value = "standard")]
    security_level: SecurityLevelArg,
    #[arg(long, global = true, value_enum)]
    intensity: Option<IntensityArg>,
    #[arg(long, global = true)]
    scheduler_mu: Option<f64>,
    #[arg(long, global = true)]
    scheduler_precision: Option<u32>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum SecurityLevelArg {
    Toy,
    Standard,
    Paranoid,
}

impl From<SecurityLevelArg> for SecurityLevel {
    fn from(arg: SecurityLevelArg) -> Self {
        match arg {
            SecurityLevelArg::Toy => SecurityLevel::Toy,
            SecurityLevelArg::Standard => SecurityLevel::Standard,
            SecurityLevelArg::Paranoid => SecurityLevel::Paranoid,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum IntensityArg {
    Low,
    Medium,
    High,
}

impl From<IntensityArg> for PolymorphismIntensity {
    fn from(arg: IntensityArg) -> Self {
        match arg {
            IntensityArg::Low => PolymorphismIntensity::Low,
            IntensityArg::Medium => PolymorphismIntensity::Medium,
            IntensityArg::High => PolymorphismIntensity::High,
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a polymorphic key bundle and write it to disk.
    Keygen {
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
    },
    /// KEM encapsulation only (exports shared key + KEM ciphertext).
    KemEncaps {
        #[arg(long, value_name = "FILE")]
        keys: PathBuf,
        #[arg(long)]
        seed: String,
        #[arg(long, value_name = "N")]
        index: u64,
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
        #[arg(long, value_name = "FILE")]
        shared_key_out: Option<PathBuf>,
    },
    /// KEM decapsulation (outputs shared key).
    KemDecaps {
        #[arg(long, value_name = "FILE")]
        keys: PathBuf,
        #[arg(long)]
        seed: String,
        #[arg(long, value_name = "N")]
        index: u64,
        #[arg(long, value_name = "FILE")]
        kem: PathBuf,
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
    },
    /// Encrypt a file using the polymorphic KEM+AEAD pipeline.
    EncryptFile {
        #[arg(long, value_name = "FILE")]
        keys: PathBuf,
        #[arg(long)]
        seed: String,
        #[arg(long, value_name = "N")]
        index: u64,
        #[arg(long, value_name = "FILE")]
        input: PathBuf,
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
        #[arg(long, value_name = "TEXT")]
        aad: Option<String>,
        #[arg(long)]
        enable_multiview: bool,
        #[arg(long, value_name = "FILE")]
        cover_file: Option<PathBuf>,
        #[arg(long, value_name = "TEXT")]
        cover_message: Option<String>,
    },
    /// Decrypt a payload produced by `encrypt-file`.
    DecryptFile {
        #[arg(long, value_name = "FILE")]
        keys: PathBuf,
        #[arg(long)]
        seed: String,
        #[arg(long, value_name = "N")]
        index: u64,
        #[arg(long, value_name = "FILE")]
        cipher: PathBuf,
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
        #[arg(long)]
        decrypt_inner: bool,
        #[arg(long)]
        decrypt_cover: bool,
    },
    /// Encrypt a message using the polymorphic engine and a stored key bundle.
    Encrypt {
        #[arg(long, value_name = "FILE")]
        keys: PathBuf,
        #[arg(long)]
        seed: String,
        #[arg(long, value_name = "N")]
        index: u64,
        #[arg(long, value_name = "TEXT")]
        message: Option<String>,
        #[arg(long, value_name = "FILE")]
        input: Option<PathBuf>,
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
    },
    /// Decrypt a ciphertext produced by the CLI.
    Decrypt {
        #[arg(long, value_name = "FILE")]
        keys: PathBuf,
        #[arg(long)]
        seed: String,
        #[arg(long, value_name = "N")]
        index: u64,
        #[arg(long, value_name = "FILE")]
        cipher: PathBuf,
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,
    },
    /// Run the legacy multi-message demo inline.
    Demo {
        #[arg(long, default_value = "phase1-demo-seed-material")]
        seed: String,
        #[arg(long, default_value_t = 3)]
        count: u64,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_logging(cli.debug);
    let fingerprint = derive_context_fingerprint(cli.context.as_deref());
    let security_level: SecurityLevel = cli.security_level.into();
    let preset = security_preset(security_level);
    let intensity: PolymorphismIntensity = cli
        .intensity
        .map(Into::into)
        .unwrap_or(preset.default_intensity);
    let scheduler_params = SchedulerParams {
        mu: cli.scheduler_mu.unwrap_or(preset.scheduler.mu),
        precision: cli
            .scheduler_precision
            .unwrap_or(preset.scheduler.precision),
    };
    match cli.command {
        Commands::Keygen { out } => cmd_keygen(out, preset),
        Commands::Encrypt {
            keys,
            seed,
            index,
            message,
            input,
            out,
        } => cmd_encrypt(
            keys,
            seed,
            index,
            message,
            input,
            out,
            preset,
            scheduler_params,
            intensity,
            &fingerprint,
        ),
        Commands::Decrypt {
            keys,
            seed,
            index,
            cipher,
            out,
        } => cmd_decrypt(
            keys,
            seed,
            index,
            cipher,
            out,
            preset,
            scheduler_params,
            intensity,
            &fingerprint,
        ),
        Commands::Demo { seed, count } => cmd_demo(
            seed,
            count,
            preset,
            scheduler_params,
            intensity,
            &fingerprint,
        ),
        Commands::KemEncaps {
            keys,
            seed,
            index,
            out,
            shared_key_out,
        } => cmd_kem_encaps(
            keys,
            seed,
            index,
            out,
            shared_key_out,
            preset,
            scheduler_params,
            intensity,
            &fingerprint,
        ),
        Commands::KemDecaps {
            keys,
            seed,
            index,
            kem,
            out,
        } => cmd_kem_decaps(
            keys,
            seed,
            index,
            kem,
            out,
            preset,
            scheduler_params,
            intensity,
            &fingerprint,
        ),
        Commands::EncryptFile {
            keys,
            seed,
            index,
            input,
            out,
            aad,
            enable_multiview,
            cover_file,
            cover_message,
        } => cmd_encrypt_file(
            keys,
            seed,
            index,
            input,
            out,
            aad,
            enable_multiview,
            cover_file,
            cover_message,
            preset,
            scheduler_params,
            intensity,
            &fingerprint,
        ),
        Commands::DecryptFile {
            keys,
            seed,
            index,
            cipher,
            out,
            decrypt_inner,
            decrypt_cover,
        } => cmd_decrypt_file(
            keys,
            seed,
            index,
            cipher,
            out,
            decrypt_inner,
            decrypt_cover,
            preset,
            scheduler_params,
            intensity,
            &fingerprint,
        ),
    }
}

fn init_logging(debug: bool) {
    let default = if debug { "debug" } else { "info" };
    let mut builder = env_logger::Builder::from_env(Env::default().default_filter_or(default));
    builder.format_timestamp(None);
    if debug {
        builder.filter_level(LevelFilter::Debug);
    }
    let _ = builder.try_init();
}

fn build_engine(
    preset: SecurityPreset,
    params: SchedulerParams,
    intensity: PolymorphismIntensity,
) -> PolymorphismEngine<'static> {
    PolymorphismEngine::new(preset.registry)
        .with_scheduler(ChaoticScheduler::new(params.mu, params.precision))
        .with_intensity(intensity)
}

fn cmd_keygen(out: PathBuf, preset: SecurityPreset) -> Result<()> {
    let bundle = keygen_bundle(preset.registry);
    save_json(&out, "key bundle", &bundle)?;
    println!("Wrote polymorphic key bundle to {}", out.display());
    println!(
        "Profiles covered: {:?}",
        bundle.public.profiles().collect::<Vec<_>>()
    );
    debug!(
        "key bundle version={} public_keys={} secret_keys={}",
        bundle.version,
        bundle.public.keys.len(),
        bundle.secret.keys.len()
    );
    Ok(())
}

fn cmd_encrypt(
    keys_path: PathBuf,
    seed: String,
    index: u64,
    message: Option<String>,
    input: Option<PathBuf>,
    out_path: PathBuf,
    preset: SecurityPreset,
    scheduler: SchedulerParams,
    intensity: PolymorphismIntensity,
    fingerprint: &[u8],
) -> Result<()> {
    let bundle = load_keys(&keys_path)?;
    let plaintext = resolve_plaintext(message, input)?;
    let seed_bytes = session_seed(&seed, fingerprint)?;
    let engine = build_engine(preset, scheduler, intensity);
    let mut rng = OsRng;
    let selection = engine.select_profile_with_trace(&seed_bytes, index);
    println!(
        "Encrypting {} bytes with profile '{}' (slot {}).",
        plaintext.len(),
        selection.profile.name,
        selection.slot
    );
    debug!(
        "encrypt cmd selection={{slot:{}, id:{:?}, degree:{}, modulus:{}, submode:{}, chaos:{}, node:{}, encoding:{:?}}}",
        selection.slot,
        selection.profile.id,
        selection.profile.ring.degree,
        selection.profile.ring.modulus,
        selection.submode_bits,
        selection.chaotic_value,
        selection.graph_node,
        selection.encoding
    );
    let ciphertext = encrypt(
        &engine,
        &bundle.public,
        &seed_bytes,
        index,
        &plaintext,
        &mut rng,
    )?;
    save_json(&out_path, "ciphertext", &ciphertext)?;
    println!(
        "Wrote ciphertext (profile {:?}) to {}",
        ciphertext.profile,
        out_path.display()
    );
    Ok(())
}

fn cmd_decrypt(
    keys_path: PathBuf,
    seed: String,
    index: u64,
    cipher_path: PathBuf,
    out: Option<PathBuf>,
    preset: SecurityPreset,
    scheduler: SchedulerParams,
    intensity: PolymorphismIntensity,
    fingerprint: &[u8],
) -> Result<()> {
    let bundle = load_keys(&keys_path)?;
    let ciphertext = load_ciphertext(&cipher_path)?;
    let seed_bytes = session_seed(&seed, fingerprint)?;
    let engine = build_engine(preset, scheduler, intensity);
    let plaintext = decrypt(&engine, &bundle.secret, &seed_bytes, index, &ciphertext)?;
    debug!(
        "decrypt cmd profile={:?} blocks={} plaintext_len={} node={}",
        ciphertext.profile,
        ciphertext.blocks.len(),
        ciphertext.plaintext_len,
        engine
            .select_profile_with_trace(&seed_bytes, index)
            .graph_node
    );
    match out {
        Some(path) => {
            fs::write(&path, &plaintext)
                .with_context(|| format!("writing plaintext to {}", path.display()))?;
            println!(
                "Recovered {} bytes and wrote them to {}",
                plaintext.len(),
                path.display()
            );
        }
        None => {
            println!("Recovered plaintext ({} bytes):", plaintext.len());
            println!("{}", String::from_utf8_lossy(&plaintext));
        }
    }
    Ok(())
}

fn cmd_kem_encaps(
    keys_path: PathBuf,
    seed: String,
    index: u64,
    kem_out: PathBuf,
    shared_key_out: Option<PathBuf>,
    preset: SecurityPreset,
    scheduler: SchedulerParams,
    intensity: PolymorphismIntensity,
    fingerprint: &[u8],
) -> Result<()> {
    let bundle = load_keys(&keys_path)?;
    let seed_bytes = session_seed(&seed, fingerprint)?;
    let engine = build_engine(preset, scheduler, intensity);
    let (kem, shared_key) = encapsulate(&engine, &bundle.public, &seed_bytes, index)?;
    save_json(&kem_out, "KEM ciphertext", &kem)?;
    let key_hex = hex_encode(shared_key);
    if let Some(out) = shared_key_out {
        fs::write(&out, key_hex.as_bytes())
            .with_context(|| format!("writing shared key to {}", out.display()))?;
    } else {
        println!("Shared key (hex): {}", key_hex);
    }
    println!(
        "Stored KEM ciphertext (profile {:?}) in {}",
        kem.ciphertext.profile,
        kem_out.display()
    );
    Ok(())
}

fn cmd_kem_decaps(
    keys_path: PathBuf,
    seed: String,
    index: u64,
    kem_path: PathBuf,
    out: Option<PathBuf>,
    preset: SecurityPreset,
    scheduler: SchedulerParams,
    intensity: PolymorphismIntensity,
    fingerprint: &[u8],
) -> Result<()> {
    let bundle = load_keys(&keys_path)?;
    let kem = load_kem(&kem_path)?;
    let seed_bytes = session_seed(&seed, fingerprint)?;
    let engine = build_engine(preset, scheduler, intensity);
    let shared_key = decapsulate(&engine, &bundle.secret, &seed_bytes, index, &kem)?;
    let key_hex = hex_encode(shared_key);
    if let Some(out_path) = out {
        fs::write(&out_path, key_hex.as_bytes())
            .with_context(|| format!("writing shared key to {}", out_path.display()))?;
        println!("Shared key written to {}", out_path.display());
    } else {
        println!("Shared key (hex): {}", key_hex);
    }
    Ok(())
}

fn cmd_encrypt_file(
    keys_path: PathBuf,
    seed: String,
    index: u64,
    input: PathBuf,
    out: PathBuf,
    aad: Option<String>,
    enable_multiview: bool,
    cover_file: Option<PathBuf>,
    cover_message: Option<String>,
    preset: SecurityPreset,
    scheduler: SchedulerParams,
    intensity: PolymorphismIntensity,
    fingerprint: &[u8],
) -> Result<()> {
    let bundle = load_keys(&keys_path)?;
    let seed_bytes = session_seed(&seed, fingerprint)?;
    let engine = build_engine(preset, scheduler, intensity);
    let plaintext =
        fs::read(&input).with_context(|| format!("reading plaintext from {}", input.display()))?;
    let aad_bytes = aad.unwrap_or_default().into_bytes();
    let mut _cover_store: Option<Vec<u8>> = None;
    let multiview_active = enable_multiview || preset.default_multiview;
    let (cover_plain, inner_plain, inner_aad) = if multiview_active {
        let data = resolve_cover_bytes(cover_file.as_ref(), cover_message.as_ref())?;
        _cover_store = Some(data);
        (
            _cover_store.as_ref().unwrap().as_slice(),
            Some(plaintext.as_slice()),
            Some(aad_bytes.as_slice()),
        )
    } else {
        (plaintext.as_slice(), None, None)
    };
    let options = PayloadOptions {
        cover_plaintext: cover_plain,
        cover_aad: aad_bytes.as_slice(),
        inner_plaintext: inner_plain,
        inner_aad: inner_aad,
    };
    let payload = encrypt_payload(
        &engine,
        &bundle.public,
        &seed_bytes,
        index,
        options,
        fingerprint,
    )?;
    save_json(&out, "payload", &payload)?;
    println!(
        "Encrypted {} bytes and stored payload in {}",
        plaintext.len(),
        out.display()
    );
    Ok(())
}

fn cmd_decrypt_file(
    keys_path: PathBuf,
    seed: String,
    index: u64,
    cipher_path: PathBuf,
    out: PathBuf,
    decrypt_inner: bool,
    decrypt_cover: bool,
    preset: SecurityPreset,
    scheduler: SchedulerParams,
    intensity: PolymorphismIntensity,
    fingerprint: &[u8],
) -> Result<()> {
    if decrypt_inner && decrypt_cover {
        bail!("Specify only one of --decrypt-inner or --decrypt-cover");
    }
    let bundle = load_keys(&keys_path)?;
    let payload = load_payload(&cipher_path)?;
    let seed_bytes = session_seed(&seed, fingerprint)?;
    let engine = build_engine(preset, scheduler, intensity);
    let view = if decrypt_inner {
        PayloadView::Inner
    } else if decrypt_cover {
        PayloadView::Cover
    } else if preset.default_inner_view {
        PayloadView::Inner
    } else {
        PayloadView::Cover
    };
    let plaintext = decrypt_payload_view(
        &engine,
        &bundle.secret,
        &seed_bytes,
        index,
        &payload,
        fingerprint,
        view,
    )?;
    fs::write(&out, &plaintext)
        .with_context(|| format!("writing plaintext to {}", out.display()))?;
    println!(
        "Recovered {} bytes and wrote them to {}",
        plaintext.len(),
        out.display()
    );
    Ok(())
}

fn cmd_demo(
    seed: String,
    count: u64,
    preset: SecurityPreset,
    scheduler: SchedulerParams,
    intensity: PolymorphismIntensity,
    fingerprint: &[u8],
) -> Result<()> {
    let engine = build_engine(preset, scheduler, intensity);
    let bundle = keygen_bundle(preset.registry);
    let mut rng = OsRng;
    let seed_bytes = session_seed(&seed, fingerprint)?;
    for idx in 0..count {
        let selection = engine.select_profile_with_trace(&seed_bytes, idx);
        let payload = format!("Phase3 demo payload #{idx}");
        debug!(
            "demo selection idx={} slot={} profile={:?} submode={} chaos={} node={}",
            idx,
            selection.slot,
            selection.profile.id,
            selection.submode_bits,
            selection.chaotic_value,
            selection.graph_node
        );
        let ciphertext = encrypt(
            &engine,
            &bundle.public,
            &seed_bytes,
            idx,
            payload.as_bytes(),
            &mut rng,
        )?;
        let recovered = decrypt(&engine, &bundle.secret, &seed_bytes, idx, &ciphertext)?;
        println!(
            "Msg {idx}: profile '{}' (slot {}) -> '{}'",
            selection.profile.name,
            selection.slot,
            String::from_utf8_lossy(&recovered)
        );
    }
    Ok(())
}

fn resolve_plaintext(message: Option<String>, input: Option<PathBuf>) -> Result<Vec<u8>> {
    match (message, input) {
        (Some(text), None) => Ok(text.into_bytes()),
        (None, Some(path)) => {
            fs::read(&path).with_context(|| format!("reading plaintext from {}", path.display()))
        }
        (Some(_), Some(_)) => bail!("Provide either --message or --input, not both."),
        (None, None) => bail!("Provide --message TEXT or --input FILE for data to encrypt."),
    }
}

fn resolve_cover_bytes(file: Option<&PathBuf>, message: Option<&String>) -> Result<Vec<u8>> {
    if let Some(path) = file {
        return fs::read(path)
            .with_context(|| format!("reading cover data from {}", path.display()));
    }
    if let Some(text) = message {
        return Ok(text.clone().into_bytes());
    }
    Ok(b"PLUME-QE COVER".to_vec())
}

fn load_keys(path: &Path) -> Result<PolyKeyPair> {
    let data = fs::read(path).with_context(|| format!("reading keys from {}", path.display()))?;
    let bundle =
        serde_json::from_slice(&data).with_context(|| format!("parsing {}", path.display()))?;
    Ok(bundle)
}

fn load_ciphertext(path: &Path) -> Result<Ciphertext> {
    let data =
        fs::read(path).with_context(|| format!("reading ciphertext from {}", path.display()))?;
    let ct =
        serde_json::from_slice(&data).with_context(|| format!("parsing {}", path.display()))?;
    Ok(ct)
}

fn load_kem(path: &Path) -> Result<KemCiphertext> {
    load_json(path, "KEM ciphertext")
}

fn load_payload(path: &Path) -> Result<EncryptedPayload> {
    load_json(path, "payload")
}

fn load_json<T: DeserializeOwned>(path: &Path, label: &str) -> Result<T> {
    let data =
        fs::read(path).with_context(|| format!("reading {} from {}", label, path.display()))?;
    let value = serde_json::from_slice(&data)
        .with_context(|| format!("parsing {} from {}", label, path.display()))?;
    Ok(value)
}

fn save_json<T: ?Sized + serde::Serialize>(path: &Path, label: &str, value: &T) -> Result<()> {
    let serialized = serde_json::to_string_pretty(value)?;
    fs::write(path, serialized)
        .with_context(|| format!("writing {} to {}", label, path.display()))?;
    Ok(())
}

fn parse_seed(seed: &str) -> Result<Vec<u8>> {
    if let Some(hex) = seed.strip_prefix("hex:") {
        let bytes = Vec::from_hex(hex.trim())
            .with_context(|| "failed to parse hex-encoded seed".to_string())?;
        Ok(bytes)
    } else {
        Ok(seed.as_bytes().to_vec())
    }
}

fn session_seed(seed: &str, fingerprint: &[u8]) -> Result<Vec<u8>> {
    let base = parse_seed(seed)?;
    Ok(mix_seed_with_fingerprint(&base, fingerprint))
}

fn derive_context_fingerprint(user: Option<&str>) -> Vec<u8> {
    if let Some(text) = user {
        return hash_context(text.as_bytes());
    }
    let mut hasher = Hasher::new();
    hasher.update(b"plume-qe::context");
    if let Ok(host) = get_hostname() {
        hasher.update(host.to_string_lossy().as_bytes());
    }
    hasher.update(env::consts::OS.as_bytes());
    hasher.update(env::consts::ARCH.as_bytes());
    if let Ok(user) = env::var("USER").or_else(|_| env::var("USERNAME")) {
        hasher.update(user.as_bytes());
    }
    hasher.finalize().as_bytes().to_vec()
}

fn hash_context(data: &[u8]) -> Vec<u8> {
    let mut hasher = Hasher::new();
    hasher.update(b"plume-qe::context");
    hasher.update(data);
    hasher.finalize().as_bytes().to_vec()
}
