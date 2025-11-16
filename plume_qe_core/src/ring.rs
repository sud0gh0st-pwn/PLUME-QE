use rand::Rng;
use rand::distributions::{Distribution, Uniform};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use zeroize::Zeroize;

/// Backend interface for ring arithmetic. Individual profiles can
/// eventually select different implementations (e.g. NTT vs schoolbook).
pub trait RingBackend: Send + Sync {
    fn add(&self, lhs: &RingElement, rhs: &RingElement) -> RingElement;
    fn sub(&self, lhs: &RingElement, rhs: &RingElement) -> RingElement;
    fn mul(&self, lhs: &RingElement, rhs: &RingElement) -> RingElement;
    fn mul_ntt(&self, lhs: &RingElement, rhs: &RingElement) -> RingElement {
        self.mul(lhs, rhs)
    }
    fn ntt(&self, poly: &mut RingElement);
    fn intt(&self, poly: &mut RingElement);
}

/// Default backend that uses the dense schoolbook implementation.
struct SchoolbookBackend;

impl RingBackend for SchoolbookBackend {
    fn add(&self, lhs: &RingElement, rhs: &RingElement) -> RingElement {
        assert_eq!(lhs.params, rhs.params);
        let coeffs = lhs
            .coeffs
            .iter()
            .zip(rhs.coeffs.iter())
            .map(|(a, b)| lhs.params.reduce(a + b))
            .collect();
        RingElement::from_coeffs(lhs.params, coeffs)
    }

    fn sub(&self, lhs: &RingElement, rhs: &RingElement) -> RingElement {
        assert_eq!(lhs.params, rhs.params);
        let coeffs = lhs
            .coeffs
            .iter()
            .zip(rhs.coeffs.iter())
            .map(|(a, b)| lhs.params.reduce(a - b))
            .collect();
        RingElement::from_coeffs(lhs.params, coeffs)
    }

    fn mul(&self, lhs: &RingElement, rhs: &RingElement) -> RingElement {
        assert_eq!(lhs.params, rhs.params);
        let n = lhs.params.degree;
        let mut tmp = vec![0i64; n];
        for (i, &a) in lhs.coeffs.iter().enumerate() {
            for (j, &b) in rhs.coeffs.iter().enumerate() {
                let mut idx = i + j;
                let mut value = a * b;
                if idx >= n {
                    idx -= n;
                    value = -value;
                }
                tmp[idx] = lhs.params.reduce(tmp[idx] + value);
            }
        }
        RingElement::from_coeffs(lhs.params, tmp)
    }

    fn ntt(&self, _poly: &mut RingElement) {}

    fn intt(&self, _poly: &mut RingElement) {}
}

static SCHOOLBOOK_BACKEND: SchoolbookBackend = SchoolbookBackend;

fn ntt_backend_for(params: &RingParams) -> &'static dyn RingBackend {
    match (params.degree, params.modulus) {
        (32, 12289) => {
            static STANDARD_ALPHA_NTT: OnceLock<NttBackend> = OnceLock::new();
            STANDARD_ALPHA_NTT.get_or_init(|| NttBackend::new(*params)) as &dyn RingBackend
        }
        (32, 40961) => {
            static STANDARD_BETA_NTT: OnceLock<NttBackend> = OnceLock::new();
            STANDARD_BETA_NTT.get_or_init(|| NttBackend::new(*params)) as &dyn RingBackend
        }
        (64, 65537) => {
            static PARANOID_BETA_NTT: OnceLock<NttBackend> = OnceLock::new();
            PARANOID_BETA_NTT.get_or_init(|| NttBackend::new(*params)) as &dyn RingBackend
        }
        (64, 786433) => {
            static PARANOID_GAMMA_NTT: OnceLock<NttBackend> = OnceLock::new();
            PARANOID_GAMMA_NTT.get_or_init(|| NttBackend::new(*params)) as &dyn RingBackend
        }
        _ => panic!("NTT backend not configured for {:?}", params),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BackendHint {
    Schoolbook,
    Ntt,
}

impl BackendHint {
    const fn schoolbook() -> Self {
        BackendHint::Schoolbook
    }

    const fn ntt() -> Self {
        BackendHint::Ntt
    }
}

fn backend_hint_default() -> BackendHint {
    BackendHint::Schoolbook
}

/// Parameters describing the polynomial ring `Z_q[x]/(x^n + 1)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RingParams {
    pub degree: usize,
    pub modulus: i64,
    pub plaintext_modulus: i64,
    #[serde(skip_serializing)]
    #[serde(skip_deserializing, default = "backend_hint_default")]
    backend_hint: BackendHint,
}

impl RingParams {
    pub const fn new(degree: usize, modulus: i64, plaintext_modulus: i64) -> Self {
        Self {
            degree,
            modulus,
            plaintext_modulus,
            backend_hint: BackendHint::schoolbook(),
        }
    }

    pub const fn new_ntt(degree: usize, modulus: i64, plaintext_modulus: i64) -> Self {
        Self {
            degree,
            modulus,
            plaintext_modulus,
            backend_hint: BackendHint::ntt(),
        }
    }

    pub fn scaling_factor(&self) -> i64 {
        let factor = self.modulus / self.plaintext_modulus;
        factor.max(1)
    }

    pub fn reduce(&self, value: i64) -> i64 {
        let mut v = value % self.modulus;
        if v < 0 {
            v += self.modulus;
        }
        v
    }

    pub fn center(&self, value: i64) -> i64 {
        let mut v = self.reduce(value);
        let half = self.modulus / 2;
        if v > half {
            v -= self.modulus;
        }
        v
    }

    pub fn backend(&self) -> &'static dyn RingBackend {
        match self.backend_hint {
            BackendHint::Schoolbook => &SCHOOLBOOK_BACKEND,
            BackendHint::Ntt => ntt_backend_for(self),
        }
    }

    pub fn uses_ntt(&self) -> bool {
        matches!(self.backend_hint, BackendHint::Ntt)
    }
}

/// Polynomial in the configured ring.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RingElement {
    params: RingParams,
    coeffs: Vec<i64>,
}

impl Zeroize for RingElement {
    fn zeroize(&mut self) {
        for coeff in &mut self.coeffs {
            *coeff = 0;
        }
    }
}

impl RingElement {
    pub fn zero(params: RingParams) -> Self {
        Self {
            params,
            coeffs: vec![0; params.degree],
        }
    }

    pub fn from_coeffs(params: RingParams, coeffs: Vec<i64>) -> Self {
        assert_eq!(
            coeffs.len(),
            params.degree,
            "coefficient vector must match degree"
        );
        let coeffs = coeffs.into_iter().map(|c| params.reduce(c)).collect();
        Self { params, coeffs }
    }

    pub fn params(&self) -> RingParams {
        self.params
    }

    pub fn coeffs(&self) -> &[i64] {
        &self.coeffs
    }

    pub fn add(&self, other: &Self) -> Self {
        self.params.backend().add(self, other)
    }

    pub fn sub(&self, other: &Self) -> Self {
        self.params.backend().sub(self, other)
    }

    pub fn mul(&self, other: &Self) -> Self {
        self.params.backend().mul(self, other)
    }

    pub fn mul_ntt(&self, other: &Self) -> Self {
        self.params.backend().mul_ntt(self, other)
    }

    pub fn mul_schoolbook(&self, other: &Self) -> Self {
        SCHOOLBOOK_BACKEND.mul(self, other)
    }

    pub fn ntt(&mut self) {
        self.params.backend().ntt(self);
    }

    pub fn intt(&mut self) {
        self.params.backend().intt(self);
    }

    pub fn random_uniform<R: Rng + ?Sized>(params: RingParams, rng: &mut R) -> Self {
        let dist = Uniform::from(0..params.modulus);
        let coeffs = (0..params.degree)
            .map(|_| dist.sample(rng))
            .collect::<Vec<_>>();
        Self::from_coeffs(params, coeffs)
    }

    pub fn sample_noise<R: Rng + ?Sized>(params: RingParams, width: i64, rng: &mut R) -> Self {
        let dist = Uniform::from(-width..=width);
        let coeffs = (0..params.degree)
            .map(|_| dist.sample(rng))
            .collect::<Vec<_>>();
        Self::from_coeffs(params, coeffs)
    }
}

struct NttBackend {
    params: RingParams,
    modulus: i64,
    forward_roots: Vec<i64>,
    inverse_roots: Vec<i64>,
    psi_pows: Vec<i64>,
    psi_inv_pows: Vec<i64>,
    inv_degree: i64,
}

impl NttBackend {
    fn new(params: RingParams) -> Self {
        assert!(
            params.degree.is_power_of_two(),
            "NTT degree must be power of two"
        );
        let modulus = params.modulus;
        let two_degree = (params.degree * 2) as i64;
        assert!(
            (modulus - 1) % two_degree == 0,
            "modulus must support 2n-th roots of unity"
        );
        let generator = primitive_root(modulus);
        let psi = mod_pow(generator, (modulus - 1) / two_degree, modulus);
        let psi_inv = mod_inv(psi, modulus);
        let omega = mod_mul(psi, psi, modulus);
        let omega_inv = mod_inv(omega, modulus);
        debug_assert_eq!(mod_pow(psi, two_degree, modulus), 1);
        debug_assert_eq!(mod_pow(psi, two_degree / 2, modulus), modulus - 1);
        let forward_roots = build_stage_roots(omega, params.degree, modulus);
        let inverse_roots = build_stage_roots(omega_inv, params.degree, modulus);
        let psi_pows = build_pow_table(psi, params.degree, modulus);
        let psi_inv_pows = build_pow_table(psi_inv, params.degree, modulus);
        let inv_degree = mod_inv(params.degree as i64, modulus);
        Self {
            params,
            modulus,
            forward_roots,
            inverse_roots,
            psi_pows,
            psi_inv_pows,
            inv_degree,
        }
    }

    fn forward_ntt(&self, coeffs: &mut [i64]) {
        for (value, twist) in coeffs.iter_mut().zip(self.psi_pows.iter()) {
            *value = mod_mul(*value, *twist, self.modulus);
        }
        self.cooley_tukey(coeffs, &self.forward_roots);
    }

    fn inverse_ntt(&self, coeffs: &mut [i64]) {
        self.cooley_tukey(coeffs, &self.inverse_roots);
        for (value, twist) in coeffs.iter_mut().zip(self.psi_inv_pows.iter()) {
            *value = mod_mul(*value, *twist, self.modulus);
        }
        for value in coeffs.iter_mut() {
            *value = mod_mul(*value, self.inv_degree, self.modulus);
        }
    }

    fn cooley_tukey(&self, values: &mut [i64], roots: &[i64]) {
        let n = values.len();
        bit_reverse(values);
        let mut len = 2;
        let mut stage = 0;
        while len <= n {
            let half = len / 2;
            let wlen = roots[stage];
            for start in (0..n).step_by(len) {
                let mut w = 1i64;
                for i in 0..half {
                    let u = values[start + i];
                    let v = mod_mul(values[start + i + half], w, self.modulus);
                    values[start + i] = mod_add(u, v, self.modulus);
                    values[start + i + half] = mod_sub(u, v, self.modulus);
                    w = mod_mul(w, wlen, self.modulus);
                }
            }
            len <<= 1;
            stage += 1;
        }
    }
}

impl RingBackend for NttBackend {
    fn add(&self, lhs: &RingElement, rhs: &RingElement) -> RingElement {
        assert_eq!(lhs.params, rhs.params);
        let coeffs = lhs
            .coeffs
            .iter()
            .zip(rhs.coeffs.iter())
            .map(|(a, b)| self.params.reduce(a + b))
            .collect();
        RingElement::from_coeffs(lhs.params, coeffs)
    }

    fn sub(&self, lhs: &RingElement, rhs: &RingElement) -> RingElement {
        assert_eq!(lhs.params, rhs.params);
        let coeffs = lhs
            .coeffs
            .iter()
            .zip(rhs.coeffs.iter())
            .map(|(a, b)| self.params.reduce(a - b))
            .collect();
        RingElement::from_coeffs(lhs.params, coeffs)
    }

    fn mul(&self, lhs: &RingElement, rhs: &RingElement) -> RingElement {
        self.mul_ntt(lhs, rhs)
    }

    fn mul_ntt(&self, lhs: &RingElement, rhs: &RingElement) -> RingElement {
        assert_eq!(lhs.params, rhs.params);
        assert_eq!(lhs.params, self.params);
        let mut lhs_coeffs = lhs.coeffs.clone();
        let mut rhs_coeffs = rhs.coeffs.clone();
        self.forward_ntt(&mut lhs_coeffs);
        self.forward_ntt(&mut rhs_coeffs);
        for (a, b) in lhs_coeffs.iter_mut().zip(rhs_coeffs.iter()) {
            *a = mod_mul(*a, *b, self.modulus);
        }
        self.inverse_ntt(&mut lhs_coeffs);
        RingElement::from_coeffs(lhs.params, lhs_coeffs)
    }

    fn ntt(&self, poly: &mut RingElement) {
        assert_eq!(poly.params, self.params);
        let mut coeffs = poly.coeffs.clone();
        self.forward_ntt(&mut coeffs);
        poly.coeffs = coeffs;
    }

    fn intt(&self, poly: &mut RingElement) {
        assert_eq!(poly.params, self.params);
        let mut coeffs = poly.coeffs.clone();
        self.inverse_ntt(&mut coeffs);
        poly.coeffs = coeffs;
    }
}

fn build_stage_roots(root: i64, degree: usize, modulus: i64) -> Vec<i64> {
    let mut roots = Vec::new();
    let mut len = 2;
    while len <= degree {
        let step = degree / len;
        roots.push(mod_pow(root, step as i64, modulus));
        len <<= 1;
    }
    roots
}

fn build_pow_table(base: i64, degree: usize, modulus: i64) -> Vec<i64> {
    let mut table = Vec::with_capacity(degree);
    let mut value = 1i64;
    for _ in 0..degree {
        table.push(value);
        value = mod_mul(value, base, modulus);
    }
    table
}

fn bit_reverse(values: &mut [i64]) {
    let n = values.len();
    let mut j = 0usize;
    for i in 1..n {
        let mut bit = n >> 1;
        while j & bit != 0 {
            j ^= bit;
            bit >>= 1;
        }
        j ^= bit;
        if i < j {
            values.swap(i, j);
        }
    }
}

fn mod_add(a: i64, b: i64, modulus: i64) -> i64 {
    let mut res = a + b;
    if res >= modulus {
        res -= modulus;
    }
    res
}

fn mod_sub(a: i64, b: i64, modulus: i64) -> i64 {
    let mut res = a - b;
    if res < 0 {
        res += modulus;
    }
    res
}

fn mod_mul(a: i64, b: i64, modulus: i64) -> i64 {
    let product = ((a as i128) * (b as i128)) % (modulus as i128);
    let mut res = product as i64;
    if res < 0 {
        res += modulus;
    }
    res
}

fn mod_pow(mut base: i64, mut exp: i64, modulus: i64) -> i64 {
    let mut result = 1i64;
    base = base % modulus;
    while exp > 0 {
        if exp & 1 == 1 {
            result = mod_mul(result, base, modulus);
        }
        base = mod_mul(base, base, modulus);
        exp >>= 1;
    }
    result
}

fn mod_inv(value: i64, modulus: i64) -> i64 {
    let (g, x, _) = extended_gcd(value, modulus);
    assert_eq!(g, 1, "value and modulus must be coprime");
    let mut res = x % modulus;
    if res < 0 {
        res += modulus;
    }
    res
}

fn extended_gcd(a: i64, b: i64) -> (i64, i64, i64) {
    if b == 0 {
        (a, 1, 0)
    } else {
        let (g, x1, y1) = extended_gcd(b, a % b);
        (g, y1, x1 - (a / b) * y1)
    }
}

fn primitive_root(modulus: i64) -> i64 {
    let phi = modulus - 1;
    let factors = factorize(phi);
    'outer: for cand in 2..modulus {
        for &factor in &factors {
            if mod_pow(cand, phi / factor, modulus) == 1 {
                continue 'outer;
            }
        }
        return cand;
    }
    panic!("no primitive root for modulus {}", modulus);
}

fn factorize(mut n: i64) -> Vec<i64> {
    let mut factors = Vec::new();
    let mut p = 2i64;
    while p * p <= n {
        if n % p == 0 {
            factors.push(p);
            while n % p == 0 {
                n /= p;
            }
        }
        p += 1;
    }
    if n > 1 {
        factors.push(n);
    }
    factors
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn ntt_roundtrip_preserves_coeffs() {
        let params = RingParams::new_ntt(32, 12289, 256);
        let mut rng = rand::thread_rng();
        for _ in 0..16 {
            let mut element = RingElement::random_uniform(params, &mut rng);
            let original = element.clone();
            element.ntt();
            element.intt();
            assert_eq!(element, original);
        }
    }

    #[test]
    fn ntt_mul_matches_schoolbook() {
        let params_ntt = RingParams::new_ntt(32, 12289, 256);
        let params_slow = RingParams::new(32, 12289, 256);
        let mut rng = rand::thread_rng();
        for _ in 0..32 {
            let coeffs_a = (0..params_ntt.degree)
                .map(|_| rng.gen_range(0..params_ntt.modulus))
                .collect::<Vec<_>>();
            let coeffs_b = (0..params_ntt.degree)
                .map(|_| rng.gen_range(0..params_ntt.modulus))
                .collect::<Vec<_>>();
            let a_ntt = RingElement::from_coeffs(params_ntt, coeffs_a.clone());
            let b_ntt = RingElement::from_coeffs(params_ntt, coeffs_b.clone());
            let a_slow = RingElement::from_coeffs(params_slow, coeffs_a);
            let b_slow = RingElement::from_coeffs(params_slow, coeffs_b);
            let expected = a_slow.mul(&b_slow);
            let actual = a_ntt.mul_ntt(&b_ntt);
            assert_eq!(expected.coeffs(), actual.coeffs());
        }
    }
}
