use crate::ring::RingParams;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProfileId(pub u16);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub id: ProfileId,
    pub name: &'static str,
    pub ring: RingParams,
    pub noise_width: i64,
}

const PROFILE_PHASE1_TINY: Profile = Profile {
    id: ProfileId(0),
    name: "phase1-tiny",
    ring: RingParams::new(16, 65536, 256),
    noise_width: 3,
};

const PROFILE_PHASE1_BALANCED: Profile = Profile {
    id: ProfileId(1),
    name: "phase1-balanced",
    ring: RingParams::new(32, 65536, 256),
    noise_width: 3,
};

const PROFILE_PHASE1_DEEP: Profile = Profile {
    id: ProfileId(2),
    name: "phase1-deep",
    ring: RingParams::new(16, 131072, 256),
    noise_width: 5,
};

static PROFILE_SET_PHASE1: [Profile; 3] = [
    PROFILE_PHASE1_TINY,
    PROFILE_PHASE1_BALANCED,
    PROFILE_PHASE1_DEEP,
];

const PROFILE_STANDARD_ALPHA: Profile = Profile {
    id: ProfileId(10),
    name: "standard-alpha",
    ring: RingParams::new_ntt(32, 12289, 256),
    noise_width: 4,
};

const PROFILE_STANDARD_BETA: Profile = Profile {
    id: ProfileId(11),
    name: "standard-beta",
    ring: RingParams::new_ntt(32, 40961, 256),
    noise_width: 5,
};

const PROFILE_PARANOID_ALPHA: Profile = Profile {
    id: ProfileId(20),
    name: "paranoid-alpha",
    ring: RingParams::new(48, 262144, 256),
    noise_width: 6,
};

const PROFILE_PARANOID_BETA: Profile = Profile {
    id: ProfileId(21),
    name: "paranoid-beta",
    ring: RingParams::new_ntt(64, 65537, 256),
    noise_width: 7,
};

const PROFILE_PARANOID_GAMMA: Profile = Profile {
    id: ProfileId(22),
    name: "paranoid-gamma",
    ring: RingParams::new_ntt(64, 786433, 256),
    noise_width: 8,
};

static PROFILE_SET_STANDARD: [Profile; 2] = [PROFILE_STANDARD_ALPHA, PROFILE_STANDARD_BETA];
static PROFILE_SET_PARANOID: [Profile; 3] = [
    PROFILE_PARANOID_ALPHA,
    PROFILE_PARANOID_BETA,
    PROFILE_PARANOID_GAMMA,
];

#[derive(Clone, Copy, Debug)]
pub struct ProfileRegistry<'a> {
    profiles: &'a [Profile],
}

impl<'a> ProfileRegistry<'a> {
    pub const fn new(profiles: &'a [Profile]) -> Self {
        Self { profiles }
    }

    pub fn phase1() -> ProfileRegistry<'static> {
        ProfileRegistry {
            profiles: &PROFILE_SET_PHASE1,
        }
    }

    pub fn standard() -> ProfileRegistry<'static> {
        ProfileRegistry {
            profiles: &PROFILE_SET_STANDARD,
        }
    }

    pub fn paranoid() -> ProfileRegistry<'static> {
        ProfileRegistry {
            profiles: &PROFILE_SET_PARANOID,
        }
    }

    pub fn profiles(&self) -> &'a [Profile] {
        self.profiles
    }

    pub fn profile_by_id(&self, id: ProfileId) -> Option<&'a Profile> {
        self.profiles.iter().find(|profile| profile.id == id)
    }
}

/// Returns the default tiny Phase 1 profile (useful for unit tests).
pub fn profile_phase1() -> Profile {
    PROFILE_PHASE1_TINY
}

/// Returns all Phase 1 profiles in priority order.
pub fn phase1_profiles() -> &'static [Profile] {
    &PROFILE_SET_PHASE1
}

pub fn standard_profiles() -> &'static [Profile] {
    &PROFILE_SET_STANDARD
}

pub fn paranoid_profiles() -> &'static [Profile] {
    &PROFILE_SET_PARANOID
}

pub fn registry_standard() -> ProfileRegistry<'static> {
    ProfileRegistry::standard()
}

pub fn registry_paranoid() -> ProfileRegistry<'static> {
    ProfileRegistry::paranoid()
}
