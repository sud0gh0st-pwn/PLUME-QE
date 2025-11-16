use blake3::Hasher;

pub fn mix_seed_with_fingerprint(seed: &[u8], fingerprint: &[u8]) -> Vec<u8> {
    let mut hasher = Hasher::new();
    hasher.update(b"plume-qe::seed-mix");
    hasher.update(seed);
    hasher.update(fingerprint);
    hasher.finalize().as_bytes().to_vec()
}

pub fn fingerprint_tag(fingerprint: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"plume-qe::fingerprint");
    hasher.update(fingerprint);
    let digest = hasher.finalize();
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&digest.as_bytes()[..32]);
    tag
}
