use crate::profiles::ProfileRegistry;
use crate::scheduler::SchedulerParams;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityLevel {
    Toy,
    Standard,
    Paranoid,
}

#[derive(Clone, Copy, Debug)]
pub struct SecurityPreset {
    pub level: SecurityLevel,
    pub registry: ProfileRegistry<'static>,
    pub scheduler: SchedulerParams,
    pub default_multiview: bool,
    pub default_inner_view: bool,
    pub default_intensity: PolymorphismIntensity,
}

pub fn security_preset(level: SecurityLevel) -> SecurityPreset {
    match level {
        SecurityLevel::Toy => SecurityPreset {
            level,
            registry: ProfileRegistry::phase1(),
            scheduler: SchedulerParams::new(3.90, 40),
            default_multiview: false,
            default_inner_view: false,
            default_intensity: PolymorphismIntensity::Low,
        },
        SecurityLevel::Standard => SecurityPreset {
            level,
            registry: ProfileRegistry::standard(),
            scheduler: SchedulerParams::new(3.97, 48),
            default_multiview: true,
            default_inner_view: false,
            default_intensity: PolymorphismIntensity::Medium,
        },
        SecurityLevel::Paranoid => SecurityPreset {
            level,
            registry: ProfileRegistry::paranoid(),
            scheduler: SchedulerParams::new(3.99, 54),
            default_multiview: true,
            default_inner_view: true,
            default_intensity: PolymorphismIntensity::High,
        },
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolymorphismIntensity {
    Low,
    Medium,
    High,
}

impl PolymorphismIntensity {
    pub fn message_stride(self) -> u64 {
        match self {
            PolymorphismIntensity::Low => 1,
            PolymorphismIntensity::Medium => 2,
            PolymorphismIntensity::High => 4,
        }
    }
}
