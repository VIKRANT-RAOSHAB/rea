import type {
  ApplicationEdge,
  ApplicationNode,
} from "./javascriptApplicationGraphSchemas.js";
import type { JavaScriptApplicationGraph } from "./javascriptApplicationGraph.js";
import { compareUnicodeCodePoints } from "../unicodeCodePointOrder.js";

interface AdjacencyEntry {
  readonly edge: ApplicationEdge;
  readonly nextNodeId: string;
}

interface Predecessor {
  readonly previousNodeId: string;
  readonly edgeId: string;
}

/** Complete reachable graph projection plus the first deterministic path to each node. */
export interface ApplicationFeatureTraversal {
  readonly nodes: ApplicationNode[];
  readonly edges: ApplicationEdge[];
  /**
   * One map per single-direction walk, in walk order. Each map's chains use
   * only that walk's edges; a node's path comes from the first map naming it.
   */
  readonly predecessors: readonly ReadonlyMap<string, Predecessor>[];
}

/** Traverse a JAG without treating edge inference as observed reachability. */
export const traverseApplicationFeature = (
  graph: JavaScriptApplicationGraph,
  seedNodeIds: readonly string[],
  direction: "outgoing" | "incoming" | "both",
): ApplicationFeatureTraversal => {
  const scope: TraversalScope = {
    nodeById: new Map(graph.nodes.map((node) => [node.node_id, node])),
    visited: new Set(seedNodeIds),
    retainedEdges: new Map<string, ApplicationEdge>(),
  };
  // "both" is the union of what the seeds reach and what reaches them. A walk
  // that could reverse direction midway would leave a seed through a shared
  // container and return everything that container holds.
  const predecessors = (
    direction === "both" ? (["outgoing", "incoming"] as const) : [direction]
  ).map((walk) =>
    collectReachable(scope, buildAdjacency(graph.edges, walk), seedNodeIds),
  );
  return {
    nodes: [...scope.visited]
      .map((nodeId) => scope.nodeById.get(nodeId))
      .filter((node): node is ApplicationNode => node !== undefined)
      .sort((left, right) =>
        compareUnicodeCodePoints(left.node_id, right.node_id),
      ),
    edges: [...scope.retainedEdges.values()].sort((left, right) =>
      compareUnicodeCodePoints(left.edge_id, right.edge_id),
    ),
    predecessors,
  };
};

/** Nodes and edges collected across every walk of one traversal. */
interface TraversalScope {
  readonly nodeById: ReadonlyMap<string, ApplicationNode>;
  readonly visited: Set<string>;
  readonly retainedEdges: Map<string, ApplicationEdge>;
}

/** Breadth-first closure in one direction, keeping the first path to each node. */
const collectReachable = (
  { nodeById, visited, retainedEdges }: TraversalScope,
  adjacency: ReadonlyMap<string, AdjacencyEntry[]>,
  seedNodeIds: readonly string[],
): ReadonlyMap<string, Predecessor> => {
  const reached = new Set(seedNodeIds);
  const predecessors = new Map<string, Predecessor>();
  const queue = [...seedNodeIds];
  for (let offset = 0; offset < queue.length; offset += 1) {
    const current = queue[offset];
    if (current === undefined) continue;
    for (const entry of adjacency.get(current) ?? []) {
      retainedEdges.set(entry.edge.edge_id, entry.edge);
      if (reached.has(entry.nextNodeId)) continue;
      if (!nodeById.has(entry.nextNodeId)) continue;
      reached.add(entry.nextNodeId);
      visited.add(entry.nextNodeId);
      predecessors.set(entry.nextNodeId, {
        previousNodeId: current,
        edgeId: entry.edge.edge_id,
      });
      queue.push(entry.nextNodeId);
    }
  }
  return predecessors;
};

const buildAdjacency = (
  edges: readonly ApplicationEdge[],
  direction: "outgoing" | "incoming",
): ReadonlyMap<string, AdjacencyEntry[]> => {
  const adjacency = new Map<string, AdjacencyEntry[]>();
  for (const edge of edges)
    if (direction === "outgoing")
      addAdjacency(adjacency, edge.source_node_id, {
        edge,
        nextNodeId: edge.target_node_id,
      });
    else
      addAdjacency(adjacency, edge.target_node_id, {
        edge,
        nextNodeId: edge.source_node_id,
      });
  for (const entries of adjacency.values())
    entries.sort((left, right) =>
      compareUnicodeCodePoints(
        `${left.edge.edge_id}\0${left.nextNodeId}`,
        `${right.edge.edge_id}\0${right.nextNodeId}`,
      ),
    );
  return adjacency;
};

const addAdjacency = (
  adjacency: Map<string, AdjacencyEntry[]>,
  nodeId: string,
  entry: AdjacencyEntry,
): void => {
  const entries = adjacency.get(nodeId);
  if (entries === undefined) adjacency.set(nodeId, [entry]);
  else entries.push(entry);
};
