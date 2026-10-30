import type { ManagedMemberSelectionOptions } from "../domain/managed/managedArtifact.js";
import {
  createDeclaringTypeLookup,
  type ManagedMethod,
  type TypeRange,
} from "./ManagedMemberInspectorCore.js";
import type { ManagedMetadataLayout } from "./ManagedMetadataLayout.js";
import { managedDecodeBudget } from "./ManagedDecodeBudget.js";

export const isScopedManagedSelection = (
  options: ManagedMemberSelectionOptions | undefined,
): boolean =>
  options !== undefined &&
  (options.type_names !== undefined ||
    options.method_tokens !== undefined ||
    options.include_method_bodies === false ||
    options.type_offset !== undefined ||
    options.type_limit !== undefined);

/** Selection is evaluated against ownership ranges before member payload decoding. */
export const selectManagedMembers = (
  ranges: readonly TypeRange[],
  layout: ManagedMetadataLayout,
  options: ManagedMemberSelectionOptions | undefined,
) => {
  const scoped = isScopedManagedSelection(options);
  if (!scoped)
    return {
      scoped,
      typeRows: undefined,
      fieldRows: undefined,
      methodRows: undefined,
      includeMethodBodies: true,
      summary:
        options === undefined
          ? undefined
          : {
              type_names: [],
              method_tokens: [],
              include_method_bodies: true,
              type_offset: 0,
              type_limit: null,
              total_matching_types: ranges.length,
              returned_types: ranges.length,
              next_type_offset: null,
            },
    };
  // Account for filter sets, ownership lookup entries, matching/page arrays,
  // and selected-type membership before allocating derived indices.
  managedDecodeBudget(layout).reserve(
    ranges.length * 160 +
      (options?.type_names?.length ?? 0) * 64 +
      (options?.method_tokens?.length ?? 0) * 128,
    layout.table(2)?.offset ?? layout.rootOffset,
  );
  const typeNames = new Set(options?.type_names);
  const methodTokens = new Set(options?.method_tokens);
  const owner =
    methodTokens.size === 0
      ? undefined
      : createDeclaringTypeLookup(ranges, "method");
  const methodOwners = new Set(
    [...methodTokens].map((token) => owner?.(tokenRow(token))?.token),
  );
  const matching = ranges.filter(
    (range) =>
      (typeNames.size === 0 ||
        (range.fullName !== null && typeNames.has(range.fullName))) &&
      (methodTokens.size === 0 || methodOwners.has(range.token)),
  );
  const offset = options?.type_offset ?? 0;
  const limit = options?.type_limit ?? null;
  const selected = matching.slice(
    offset,
    limit === null ? undefined : offset + limit,
  );
  const selectedTypes = new Set(selected.map((range) => range.token));
  const totalKnown =
    typeNames.size === 0 || ranges.every((range) => range.fullName !== null);
  return {
    scoped,
    typeRows: scoped
      ? selected.map((range) => tokenRow(range.token))
      : undefined,
    fieldRows: scoped ? memberRows(selected, layout, "field") : undefined,
    methodRows: scoped
      ? methodTokens.size === 0
        ? memberRows(selected, layout, "method")
        : [...methodTokens]
            .map(tokenRow)
            .filter((row) => {
              const declared = owner?.(row);
              return (
                declared !== null &&
                declared !== undefined &&
                selectedTypes.has(declared.token)
              );
            })
            .sort((left, right) => left - right)
      : undefined,
    includeMethodBodies: options?.include_method_bodies ?? true,
    summary:
      options === undefined
        ? undefined
        : {
            type_names: options.type_names ?? [],
            method_tokens: options.method_tokens ?? [],
            include_method_bodies: options.include_method_bodies ?? true,
            type_offset: offset,
            type_limit: limit,
            total_matching_types: totalKnown ? matching.length : null,
            returned_types: selected.length,
            next_type_offset:
              offset + selected.length < matching.length
                ? offset + selected.length
                : null,
          },
  };
};

const tokenRow = (token: string): number => Number.parseInt(token.slice(4), 16);

const memberRows = (
  ranges: readonly TypeRange[],
  layout: ManagedMetadataLayout,
  kind: "field" | "method",
): readonly number[] => {
  const count = layout.table(kind === "field" ? 4 : 6)?.rowCount ?? 0;
  const bounds = (range: TypeRange) => ({
    first: Math.max(1, kind === "field" ? range.fieldStart : range.methodStart),
    end: Math.min(
      count + 1,
      kind === "field" ? range.fieldEnd : range.methodEnd,
    ),
  });
  let capacity = 0;
  for (const range of ranges) {
    const { first, end } = bounds(range);
    capacity = Math.min(count, capacity + Math.max(0, end - first));
  }
  // A row can occupy a Set entry and a sorted result array at the same time.
  managedDecodeBudget(layout).reserve(
    capacity * 64,
    layout.table(kind === "field" ? 4 : 6)?.offset ?? layout.rootOffset,
  );
  const rows = new Set<number>();
  for (const range of ranges) {
    const { first, end } = bounds(range);
    for (let row = first; row < end; row += 1) rows.add(row);
  }
  return [...rows].sort((left, right) => left - right);
};

/** Resolve only member tokens actually observed in the selected CIL. */
export const referencedMemberRows = (
  methods: readonly ManagedMethod[],
  layout: ManagedMetadataLayout,
) => {
  const anchors = methods.reduce(
    (total, method) => total + method.body.anchors.length,
    0,
  );
  managedDecodeBudget(layout).reserve(
    anchors * 64,
    layout.table(6)?.offset ?? layout.rootOffset,
  );
  const methodsRows = new Set<number>();
  const fieldRows = new Set<number>();
  const refRows = new Set<number>();
  for (const method of methods) {
    for (const anchor of method.body.anchors) {
      const token = anchor.operand;
      if (token === null || !/^0x[0-9a-f]{8}$/.test(token)) continue;
      const row = tokenRow(token);
      if (token.startsWith("0x06")) methodsRows.add(row);
      if (token.startsWith("0x04")) fieldRows.add(row);
      if (token.startsWith("0x0a")) refRows.add(row);
    }
  }
  const ordered = (rows: ReadonlySet<number>) =>
    [...rows].sort((a, b) => a - b);
  return {
    methods: ordered(methodsRows),
    fields: ordered(fieldRows),
    refs: ordered(refRows),
  };
};
