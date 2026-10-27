import { describe, expect, it } from "vitest";

import {
  createJavaScriptApplicationEdge,
  createJavaScriptApplicationGraph,
} from "./javascriptApplicationGraph.js";
import {
  artifactEvidence,
  completeCoverage,
  fixtureNode,
} from "./javascriptApplicationGraph.fixture.js";
import type {
  ApplicationEdge,
  ApplicationNode,
} from "./javascriptApplicationGraphSchemas.js";
import { traceApplicationFeature } from "./javascriptFeatureTrace.js";
import { traverseApplicationFeature } from "./javascriptFeatureTraversal.js";

const SHA = "a".repeat(64);

const node = (kind: ApplicationNode["kind"], path: string): ApplicationNode =>
  fixtureNode(
    kind,
    {
      strategy: "canonical-path",
      stability: "artifact-version",
      artifact_sha256: SHA,
      path,
    },
    path,
    {},
    artifactEvidence(SHA, path),
  );

const edge = (
  source: ApplicationNode,
  target: ApplicationNode,
  relation: ApplicationEdge["relation"],
): ApplicationEdge =>
  createJavaScriptApplicationEdge({
    source_node_id: source.node_id,
    target_node_id: target.node_id,
    relation,
    properties: {},
    evidence: artifactEvidence(SHA, source.observations[0]?.label ?? "x"),
  });

// One artifact holds two unrelated assets. Each module persists to its own
// storage key; the second module also calls an endpoint.
const root = node("artifact", "root");
const firstAsset = node("javascript-asset", "first.js");
const secondAsset = node("javascript-asset", "second.js");
const firstModule = node("javascript-module", "first.js#module");
const secondModule = node("javascript-module", "second.js#module");
const firstKey = node("storage", "first-key");
const secondKey = node("storage", "second-key");
const endpoint = node("endpoint", "rpc-second");
const graph = createJavaScriptApplicationGraph({
  schema: "JavaScriptApplicationGraph",
  root_node_ids: [root.node_id],
  nodes: [
    root,
    firstAsset,
    secondAsset,
    firstModule,
    secondModule,
    firstKey,
    secondKey,
    endpoint,
  ],
  edges: [
    edge(root, firstAsset, "contains"),
    edge(root, secondAsset, "contains"),
    edge(firstAsset, firstModule, "exposes"),
    edge(secondAsset, secondModule, "exposes"),
    edge(firstModule, firstKey, "persists_to"),
    edge(secondModule, secondKey, "persists_to"),
    edge(secondModule, endpoint, "calls"),
  ],
  coverage: completeCoverage,
  limitations: [],
});

const ids = (nodes: readonly ApplicationNode[]): string[] =>
  nodes.map(({ node_id: id }) => id).sort();

describe("traverseApplicationFeature", () => {
  it("returns the union of incoming and outgoing closures for both", () => {
    const both = traverseApplicationFeature(graph, [firstKey.node_id], "both");
    const incoming = traverseApplicationFeature(
      graph,
      [firstKey.node_id],
      "incoming",
    );
    const outgoing = traverseApplicationFeature(
      graph,
      [firstKey.node_id],
      "outgoing",
    );

    expect(ids(both.nodes)).toEqual(
      [...new Set([...ids(incoming.nodes), ...ids(outgoing.nodes)])].sort(),
    );
    expect(ids(both.nodes)).toEqual(
      ids([root, firstAsset, firstModule, firstKey]),
    );
    expect(ids(both.nodes)).not.toContain(secondKey.node_id);
    expect(ids(both.nodes)).not.toContain(endpoint.node_id);
  });

  it("keeps the shared container out of a sibling's trace paths", () => {
    const trace = traceApplicationFeature({
      sourceEvidenceId: `ev_${"b".repeat(64)}`,
      graph,
      nativeEvidence: [],
      seed: {
        kind: "string",
        value: "first-key",
        match: "exact",
        case_sensitive: true,
      },
      direction: "both",
    });

    expect(trace.summary.traced_nodes).toBe(4);
    expect(trace.paths.map(({ end_node_id: id }) => id)).toEqual([]);
  });

  it("builds each path from one direction only", () => {
    const traversal = traverseApplicationFeature(
      graph,
      [secondModule.node_id],
      "both",
    );
    const [outgoing, incoming] = traversal.predecessors;

    expect(outgoing?.get(endpoint.node_id)?.previousNodeId).toBe(
      secondModule.node_id,
    );
    expect(incoming?.get(root.node_id)?.previousNodeId).toBe(
      secondAsset.node_id,
    );
    expect(ids(traversal.nodes)).not.toContain(firstModule.node_id);
  });
});
