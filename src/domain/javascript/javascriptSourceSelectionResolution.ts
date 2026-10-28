import { compareUnicodeCodePoints } from "../unicodeCodePointOrder.js";

interface JavaScriptSourceSelectorOutcome {
  /** Resolved inventoried paths in first-request order, without duplicates. */
  readonly selectedPaths: readonly string[];
  /** Selector indexes that matched no inventoried file. */
  readonly unmatchedIndexes: readonly number[];
  /** Resolved paths whose inventoried bytes are unavailable, in resolution order. */
  readonly unavailablePaths: readonly string[];
  /** True when a folder prefix or glob resolved at least one selector. */
  readonly expanded: boolean;
  /** Unmatched nonempty selectors need complete inventory to establish absence. */
  readonly requiresCompleteInventory: boolean;
}

const hasGlobMeta = (selector: string): boolean =>
  selector.includes("*") || selector.includes("?");

/** Literal segments need no code-point expansion; wildcard segments compile once. */
type SegmentPattern = string | readonly string[];

const compilePattern = (pattern: string): readonly SegmentPattern[] => {
  const segments: SegmentPattern[] = [];
  for (const segment of pattern.split("/")) {
    if (segment === "**" && segments.at(-1) === "**") continue;
    segments.push(
      segment === "**" || !hasGlobMeta(segment) ? segment : Array.from(segment),
    );
  }
  return segments;
};

/** Match one path segment where `*` spans any run and `?` one code point. */
const matchSegment = (pattern: SegmentPattern, value: string): boolean => {
  if (typeof pattern === "string") return pattern === value;
  const patternPoints = pattern;
  const valuePoints = Array.from(value);
  let patternIndex = 0;
  let valueIndex = 0;
  let starIndex = -1;
  let starValueIndex = -1;
  while (valueIndex < valuePoints.length) {
    const patternPoint =
      patternIndex < patternPoints.length
        ? patternPoints[patternIndex]
        : undefined;
    if (
      patternPoint !== undefined &&
      (patternPoint === "?" || patternPoint === valuePoints[valueIndex])
    ) {
      patternIndex += 1;
      valueIndex += 1;
    } else if (patternPoint === "*") {
      starIndex = patternIndex;
      starValueIndex = valueIndex;
      patternIndex += 1;
    } else if (starIndex >= 0) {
      starValueIndex += 1;
      patternIndex = starIndex + 1;
      valueIndex = starValueIndex;
    } else {
      return false;
    }
  }
  while (
    patternIndex < patternPoints.length &&
    patternPoints[patternIndex] === "*"
  )
    patternIndex += 1;
  return patternIndex === patternPoints.length;
};

/** Match whole paths where a `**` segment spans zero or more segments. */
const matchSegments = (
  patternSegments: readonly SegmentPattern[],
  pathSegments: readonly string[],
): boolean => {
  let patternIndex = 0;
  let pathIndex = 0;
  let starIndex = -1;
  let starPathIndex = -1;
  while (pathIndex < pathSegments.length) {
    const patternSegment = patternSegments[patternIndex];
    const pathSegment = pathSegments[pathIndex];
    if (patternSegment === "**") {
      starIndex = patternIndex;
      starPathIndex = pathIndex;
      patternIndex += 1;
    } else if (
      patternSegment !== undefined &&
      pathSegment !== undefined &&
      matchSegment(patternSegment, pathSegment)
    ) {
      patternIndex += 1;
      pathIndex += 1;
    } else if (starIndex >= 0) {
      starPathIndex += 1;
      pathIndex = starPathIndex;
      patternIndex = starIndex + 1;
    } else return false;
  }
  while (patternSegments[patternIndex] === "**") patternIndex += 1;
  return patternIndex === patternSegments.length;
};

/**
 * Resolve caller selectors against the observed artifact inventory. An entry
 * that exactly names an inventoried path selects that path; otherwise it is a
 * folder prefix (trailing slashes ignored) or a glob where `*` matches within
 * one path segment, `**` spans whole segments and `?` matches one character.
 * Matching is case-sensitive and never touches the filesystem.
 */
export const resolveJavaScriptSourceSelection = (
  entries: readonly string[],
  inventoryPaths: readonly string[],
  unavailablePaths: ReadonlySet<string>,
): JavaScriptSourceSelectorOutcome => {
  const allPaths = new Set(inventoryPaths);
  for (const path of unavailablePaths) allPaths.add(path);
  // Exact-only requests need neither sorting nor path-segment allocations.
  let orderedPaths: readonly string[] | undefined;
  let segmentedPaths:
    | readonly { path: string; segments: readonly string[] }[]
    | undefined;
  const ordered = (): readonly string[] =>
    (orderedPaths ??= [...allPaths].sort(compareUnicodeCodePoints));
  const selectedPaths: string[] = [];
  const selected = new Set<string>();
  const unmatchedIndexes: number[] = [];
  let expanded = false;
  let requiresCompleteInventory = false;
  for (const [index, entry] of entries.entries()) {
    const base = entry.replace(/\/+$/u, "");
    let matches: readonly string[];
    if (allPaths.has(entry)) matches = [entry];
    else if (base === "") matches = [];
    else if (hasGlobMeta(base)) {
      const pattern = compilePattern(base);
      segmentedPaths ??= ordered().map((path) => ({
        path,
        segments: path.split("/"),
      }));
      matches = segmentedPaths
        .filter(({ segments }) => matchSegments(pattern, segments))
        .map(({ path }) => path);
    } else {
      const boundary = `${base}/`;
      matches = ordered().filter((path) => path.startsWith(boundary));
    }
    if (matches.length === 0) {
      unmatchedIndexes.push(index);
      if (base !== "") requiresCompleteInventory = true;
      continue;
    }
    if (!allPaths.has(entry)) expanded = true;
    for (const path of matches)
      if (!selected.has(path)) {
        selected.add(path);
        selectedPaths.push(path);
      }
  }
  return {
    selectedPaths,
    unmatchedIndexes,
    unavailablePaths: selectedPaths.filter((path) =>
      unavailablePaths.has(path),
    ),
    expanded,
    requiresCompleteInventory,
  };
};
