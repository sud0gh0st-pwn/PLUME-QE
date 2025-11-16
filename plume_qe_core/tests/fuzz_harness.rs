use plume_qe_core::{
    PolymorphismEngine, decrypt, encrypt, keygen_bundle, mix_seed_with_fingerprint,
};

#[test]
#[ignore]
fn fuzz_placeholder_roundtrip() {
    // Simple smoke fuzz harness placeholder: random bytes roundtrip.
    let engine = PolymorphismEngine::phase1();
    let bundle = keygen_bundle(engine.registry());
    for idx in 0..16u8 {
        let msg: Vec<u8> = (0..16).map(|_| rand::random::<u8>()).collect();
        let mut noise = rand::rngs::OsRng;
        let seed_bytes = mix_seed_with_fingerprint(b"fuzz-seed", b"fuzz-context");
        let ciphertext = encrypt(
            &engine,
            &bundle.public,
            &seed_bytes,
            idx as u64,
            &msg,
            &mut noise,
        )
        .expect("encrypt");
        let recovered = decrypt(
            &engine,
            &bundle.secret,
            &seed_bytes,
            idx as u64,
            &ciphertext,
        )
        .expect("decrypt");
        assert_eq!(msg, recovered);
    }
}
