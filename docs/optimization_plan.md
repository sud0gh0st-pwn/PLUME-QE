# Phase 6 – High-Performance Optimization (Design Notes)

## Baseline Observations
- Ring representation: dense `Vec<i64>` with schoolbook `O(n^2)` multiplication in `RingElement::mul`.
- Modulus handling: `RingParams::reduce` with signed correction.
- Noise sampling: naïve uniform sampling per coefficient.

## NTT Strategy
- Candidate profiles for NTT: the standard/paranoid sets use `n = 32/48/64` with moduli `q = 2^17`, `2^18`, `2^19`. These moduli are powers of 2 (not prime), so classical NTT won't work; plan is to switch to NTT-friendly primes (e.g., `q = 2^k * c + 1`) for standard/paranoid levels only.
- Approach: introduce a `RingBackend` trait with a schoolbook fallback and an `NttBackend` for prime moduli (possibly leveraging `ff`/`ark-ff` or a lightweight custom NTT).

### Proposed `RingBackend` Trait
```rust
trait RingBackend {
    fn add(&self, lhs: &RingElement, rhs: &RingElement) -> RingElement;
    fn sub(&self, lhs: &RingElement, rhs: &RingElement) -> RingElement;
    fn mul(&self, lhs: &RingElement, rhs: &RingElement) -> RingElement;
    fn ntt(&self, poly: &mut RingElement);
    fn intt(&self, poly: &mut RingElement);
}
```

Fallback implementation would ignore `ntt/intt`. Future steps include:
1. Choosing NTT-friendly primes for `standard`/`paranoid` registries.
2. Precomputing twiddle factors per profile (cache by `RingParams`).
3. Potentially reuse existing crates (e.g., `ff` or `ark-poly`) if licensing/perf works.
