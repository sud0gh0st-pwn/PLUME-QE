use blake3::Hasher;

const DEFAULT_MU: f64 = 3.99;
const DEFAULT_PRECISION: u32 = 48;

#[derive(Clone, Copy, Debug)]
pub struct SchedulerParams {
    pub mu: f64,
    pub precision: u32,
}

impl SchedulerParams {
    pub const fn new(mu: f64, precision: u32) -> Self {
        Self { mu, precision }
    }
}

impl Default for SchedulerParams {
    fn default() -> Self {
        Self {
            mu: DEFAULT_MU,
            precision: DEFAULT_PRECISION,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ChaoticScheduler {
    mu_fixed: u128,
    precision: u32,
    shift: u32,
    scale: u128,
    scale_minus_one: u128,
    scale_minus_two: u128,
}

#[derive(Clone, Copy, Debug)]
pub struct SchedulerTrace {
    pub raw_value: u128,
    pub slot: usize,
    pub submode_bits: u8,
}

impl ChaoticScheduler {
    pub fn new(mu: f64, precision: u32) -> Self {
        let precision = precision.max(16).min(60);
        let scale = 1u128 << precision;
        let mu_clamped = mu.clamp(3.5, 4.0);
        let mu_fixed = (mu_clamped * scale as f64) as u128;
        Self {
            mu_fixed,
            precision,
            shift: precision,
            scale,
            scale_minus_one: scale - 1,
            scale_minus_two: scale - 2,
        }
    }

    pub fn default() -> Self {
        let params = SchedulerParams::default();
        Self::new(params.mu, params.precision)
    }

    pub fn precision(&self) -> u32 {
        self.precision
    }

    pub fn scale(&self) -> u128 {
        self.scale
    }

    pub fn derive_trace(&self, seed: &[u8], message_index: u64, slots: usize) -> SchedulerTrace {
        let mut value = seed_to_state(seed, self.scale_minus_two);
        for _ in 0..=message_index {
            value = self.step(value);
        }
        let slots = slots.max(1);
        let slot = ((value * slots as u128) >> self.shift) as usize % slots;
        let shift = self.precision.saturating_sub(8);
        let submode_bits = ((value >> shift) & 0xFF) as u8;
        SchedulerTrace {
            raw_value: value,
            slot,
            submode_bits,
        }
    }

    #[inline(always)]
    pub fn step(&self, current: u128) -> u128 {
        iterate(
            self.mu_fixed,
            self.scale,
            self.scale_minus_one,
            self.shift,
            current,
        )
    }
}

#[inline(always)]
fn seed_to_state(seed: &[u8], scale_minus_two: u128) -> u128 {
    let mut hasher = Hasher::new();
    hasher.update(b"plume-qe::chaos-seed");
    hasher.update(seed);
    let digest = hasher.finalize();
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&digest.as_bytes()[..16]);
    let mut value = u128::from_le_bytes(buf) % scale_minus_two;
    value += 1;
    value
}

#[inline(always)]
fn iterate(mu_fixed: u128, scale: u128, scale_minus_one: u128, shift: u32, current: u128) -> u128 {
    let complement = scale - current;
    let term = ((current * complement) >> shift).min(scale_minus_one);
    ((mu_fixed * term) >> shift).clamp(1, scale_minus_one)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheduler_deterministic_trace() {
        let scheduler = ChaoticScheduler::new(3.99, 48);
        let trace = scheduler.derive_trace(b"deterministic-seed", 25, 7);
        assert_eq!(trace.raw_value, 143561910474536);
        assert_eq!(trace.slot, 3);
        assert_eq!(trace.submode_bits, 0x82);
    }

    #[test]
    fn scheduler_step_matches_trace_progression() {
        let scheduler = ChaoticScheduler::new(3.9, 40);
        let seed = b"step-seed";
        let base = scheduler.derive_trace(seed, 0, 5).raw_value;
        let mut manual = base;
        for _ in 0..5 {
            manual = scheduler.step(manual);
        }
        let advanced = scheduler.derive_trace(seed, 5, 5).raw_value;
        assert_eq!(manual, advanced);
    }
}
