//! Edge metadata connecting two workflow nodes.

use serde::{Deserialize, Serialize};

/// Describes how data flows across a single directed edge.
///
/// An edge carries a source/target handle pair, an optional data-mapping
/// expression applied to the parent's output before it reaches the child,
/// and an optional condition gate. Both expressions are opaque strings at
/// this layer — evaluation is the executor's responsibility (reference
/// implementations use Rhai; another consumer could plug in a different
/// evaluator).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct EdgeLogic {
    /// Name of the output handle on the source node.
    pub source_handle: String,
    /// Name of the input handle on the target node.
    pub target_handle: String,
    /// Optional data-mapping expression applied when data flows across
    /// this edge. Evaluated by the executor against the parent's output.
    pub mapping: Option<String>,
    /// Optional condition expression. When present, the edge is only
    /// followed if it evaluates to `true` against the parent's output.
    pub condition: Option<String>,
    /// Edge subtype label (e.g. `"conditional"`, `"default"`,
    /// `"on_failure"`). Empty string when unspecified.
    pub edge_type: String,
}
