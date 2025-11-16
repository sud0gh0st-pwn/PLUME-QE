use blake3::Hasher;

use crate::profiles::ProfileId;

#[derive(Clone, Copy, Debug)]
pub enum EncodingVariant {
    Linear,
    Wide,
    Dense,
}

#[derive(Clone, Copy, Debug)]
pub struct GraphNode {
    pub id: u8,
    pub profile_ids: &'static [ProfileId],
    pub encoding: EncodingVariant,
    pub edges: &'static [u8],
}

static NODE0_PROFILES: &[ProfileId] = &[ProfileId(0), ProfileId(1)];
static NODE1_PROFILES: &[ProfileId] = &[ProfileId(1)];
static NODE2_PROFILES: &[ProfileId] = &[ProfileId(2), ProfileId(0)];

const NODE0_EDGES: &[u8] = &[1, 2];
const NODE1_EDGES: &[u8] = &[0, 2];
const NODE2_EDGES: &[u8] = &[0, 1];

static GRAPH_NODES: &[GraphNode] = &[
    GraphNode {
        id: 0,
        profile_ids: NODE0_PROFILES,
        encoding: EncodingVariant::Linear,
        edges: NODE0_EDGES,
    },
    GraphNode {
        id: 1,
        profile_ids: NODE1_PROFILES,
        encoding: EncodingVariant::Wide,
        edges: NODE1_EDGES,
    },
    GraphNode {
        id: 2,
        profile_ids: NODE2_PROFILES,
        encoding: EncodingVariant::Dense,
        edges: NODE2_EDGES,
    },
];

#[derive(Clone, Debug)]
pub struct GraphWalk {
    nodes: &'static [GraphNode],
}

impl GraphWalk {
    pub fn phase1() -> Self {
        Self { nodes: GRAPH_NODES }
    }

    pub fn node_for_message(&self, seed: &[u8], message_index: u64) -> &'static GraphNode {
        let mut node = self.start_node(seed);
        if message_index == 0 {
            return node;
        }
        for step in 0..message_index {
            node = self.step_node(seed, step, node);
        }
        node
    }

    fn start_node(&self, seed: &[u8]) -> &'static GraphNode {
        let digest = prism(seed, 0, b"start");
        let idx = (digest % (self.nodes.len() as u64)) as usize;
        &self.nodes[idx]
    }

    fn step_node(&self, seed: &[u8], step: u64, node: &'static GraphNode) -> &'static GraphNode {
        if node.edges.is_empty() {
            return node;
        }
        let digest = prism(seed, step + node.id as u64, b"edge");
        let idx = (digest % (node.edges.len() as u64)) as usize;
        &self.nodes[node.edges[idx] as usize]
    }
}

fn prism(seed: &[u8], counter: u64, label: &[u8]) -> u64 {
    let mut hasher = Hasher::new();
    hasher.update(b"plume-qe::graph");
    hasher.update(seed);
    hasher.update(&counter.to_le_bytes());
    hasher.update(label);
    let digest = hasher.finalize();
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&digest.as_bytes()[..8]);
    u64::from_le_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_walk_same_seed() {
        let graph = GraphWalk::phase1();
        let seed = b"graph-seed";
        let path_a: Vec<_> = (0..8).map(|i| graph.node_for_message(seed, i).id).collect();
        let path_b: Vec<_> = (0..8).map(|i| graph.node_for_message(seed, i).id).collect();
        assert_eq!(path_a, path_b);
    }

    #[test]
    fn different_seed_varies_path() {
        let graph = GraphWalk::phase1();
        let seed_a = b"graph-A";
        let seed_b = b"graph-B";
        let path_a: Vec<_> = (0..5)
            .map(|i| graph.node_for_message(seed_a, i).id)
            .collect();
        let path_b: Vec<_> = (0..5)
            .map(|i| graph.node_for_message(seed_b, i).id)
            .collect();
        assert_ne!(path_a, path_b);
    }
}
