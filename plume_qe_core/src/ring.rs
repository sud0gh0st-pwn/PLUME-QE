use rand::Rng;
use rand::distributions::{Distribution, Uniform};
use serde::{Deserialize, Serialize};

/// Parameters describing the polynomial ring `Z_q[x]/(x^n + 1)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RingParams {
    pub degree: usize,
    pub modulus: i64,
    pub plaintext_modulus: i64,
}

impl RingParams {
    pub const fn new(degree: usize, modulus: i64, plaintext_modulus: i64) -> Self {
        Self {
            degree,
            modulus,
            plaintext_modulus,
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
}

/// Polynomial in the configured ring.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RingElement {
    params: RingParams,
    coeffs: Vec<i64>,
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
        assert_eq!(self.params, other.params);
        let coeffs = self
            .coeffs
            .iter()
            .zip(other.coeffs.iter())
            .map(|(a, b)| self.params.reduce(a + b))
            .collect();
        Self::from_coeffs(self.params, coeffs)
    }

    pub fn sub(&self, other: &Self) -> Self {
        assert_eq!(self.params, other.params);
        let coeffs = self
            .coeffs
            .iter()
            .zip(other.coeffs.iter())
            .map(|(a, b)| self.params.reduce(a - b))
            .collect();
        Self::from_coeffs(self.params, coeffs)
    }

    pub fn mul(&self, other: &Self) -> Self {
        assert_eq!(self.params, other.params);
        let n = self.params.degree;
        let mut tmp = vec![0i64; n];
        for (i, &a) in self.coeffs.iter().enumerate() {
            for (j, &b) in other.coeffs.iter().enumerate() {
                let mut idx = i + j;
                let mut value = a * b;
                if idx >= n {
                    idx -= n;
                    value = -value;
                }
                tmp[idx] = self.params.reduce(tmp[idx] + value);
            }
        }
        Self::from_coeffs(self.params, tmp)
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
