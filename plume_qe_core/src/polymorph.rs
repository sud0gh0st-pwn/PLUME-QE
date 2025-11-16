use std::vec::Vec;

use crate::graph::{EncodingVariant, GraphWalk};
use crate::preset::PolymorphismIntensity;
use crate::profiles::{Profile, ProfileId, ProfileRegistry};
use crate::scheduler::{ChaoticScheduler, SchedulerParams};

/// Deterministically selects profiles from a registry using a seed
/// and message counter. Phase 1 cycles over a few toy profiles to
/// exercise the polymorphic plumbing.
#[derive(Clone, Debug)]
pub struct PolymorphismEngine<'a> {
    registry: ProfileRegistry<'a>,
    scheduler: ChaoticScheduler,
    graph: GraphWalk,
    intensity: PolymorphismIntensity,
}

#[derive(Clone, Copy, Debug)]
pub struct ProfileSelection<'a> {
    pub profile: &'a Profile,
    pub slot: usize,
    pub submode_bits: u8,
    pub chaotic_value: u128,
    pub graph_node: u8,
    pub encoding: EncodingVariant,
}

impl<'a> PolymorphismEngine<'a> {
    pub fn new(registry: ProfileRegistry<'a>) -> Self {
        Self {
            registry,
            scheduler: ChaoticScheduler::default(),
            graph: GraphWalk::phase1(),
            intensity: PolymorphismIntensity::Medium,
        }
    }

    pub fn phase1() -> PolymorphismEngine<'static> {
        PolymorphismEngine::<'static>::new(ProfileRegistry::phase1())
    }

    pub fn with_scheduler(mut self, scheduler: ChaoticScheduler) -> Self {
        self.scheduler = scheduler;
        self
    }

    pub fn with_params(mut self, params: SchedulerParams) -> Self {
        self.scheduler = ChaoticScheduler::new(params.mu, params.precision);
        self
    }

    pub fn with_graph(mut self, graph: GraphWalk) -> Self {
        self.graph = graph;
        self
    }

    pub fn with_intensity(mut self, intensity: PolymorphismIntensity) -> Self {
        self.intensity = intensity;
        self
    }

    pub fn scheduler(&self) -> &ChaoticScheduler {
        &self.scheduler
    }

    pub fn graph(&self) -> &GraphWalk {
        &self.graph
    }

    pub fn registry(&self) -> ProfileRegistry<'a> {
        self.registry
    }

    pub fn select_profile(&self, seed: &[u8], message_index: u64) -> &'a Profile {
        self.select_profile_with_trace(seed, message_index).profile
    }

    pub fn select_profile_with_trace(
        &self,
        seed: &[u8],
        message_index: u64,
    ) -> ProfileSelection<'a> {
        let profiles = self.registry.profiles();
        assert!(
            !profiles.is_empty(),
            "polymorphism engine requires at least one profile"
        );
        let scaled_index = message_index.saturating_mul(self.intensity.message_stride());
        let node = self.graph.node_for_message(seed, scaled_index);
        let subset = profile_subset(node.profile_ids, &self.registry);
        let count = subset.len().max(1);
        let trace = self.scheduler.derive_trace(seed, scaled_index, count);
        let slot = trace.slot % count;
        let profile = subset
            .get(slot)
            .copied()
            .unwrap_or_else(|| profiles.get(slot % profiles.len()).unwrap());
        ProfileSelection {
            profile,
            slot,
            submode_bits: trace.submode_bits,
            chaotic_value: trace.raw_value,
            graph_node: node.id,
            encoding: node.encoding,
        }
    }
}

fn profile_subset<'a>(
    ids: &'static [ProfileId],
    registry: &ProfileRegistry<'a>,
) -> Vec<&'a Profile> {
    let mut subset = Vec::with_capacity(ids.len());
    for id in ids {
        if let Some(profile) = registry.profile_by_id(*id) {
            subset.push(profile);
        }
    }
    if subset.is_empty() {
        subset.extend(registry.profiles().iter());
    }
    subset
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn phase1_engine_switches_profiles() {
        let engine = PolymorphismEngine::phase1();
        let seed = b"cross-profile-test";
        let mut seen = HashSet::new();
        for i in 0..32 {
            let selection = engine.select_profile_with_trace(seed, i);
            seen.insert(selection.profile.id);
        }
        assert!(
            seen.len() >= 2,
            "expected more than one profile to be selected"
        );
    }

    #[test]
    fn submode_bits_vary() {
        let engine = PolymorphismEngine::phase1();
        let seed = b"submode-demo";
        let mut seen = HashSet::new();
        for i in 0..10 {
            let selection = engine.select_profile_with_trace(seed, i);
            seen.insert(selection.submode_bits);
        }
        assert!(seen.len() >= 2, "submode bits should vary");
    }
}
