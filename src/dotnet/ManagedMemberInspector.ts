import {
  admitManagedProjection,
  managedDecodeBudget,
} from "./ManagedDecodeBudget.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import {
  managedMemberInspectionSchema,
  type ManagedMemberInspection,
  type ManagedMemberSelectionOptions,
  type ManagedParseIssue,
} from "../domain/managed/managedArtifact.js";
import {
  readManagedPeLayout,
  type ManagedPeLayout,
} from "./ManagedPeReader.js";
import {
  readManagedResourceDirectory,
  managedTableRowCounts,
  readManagedMetadataInventory,
} from "./ManagedMetadataInventory.js";
import { readManagedMetadataLayout } from "./ManagedMetadataLayout.js";
import { readModule } from "./ManagedMetadataInventoryRows.js";
import {
  isScopedManagedSelection,
  referencedMemberRows,
  selectManagedMembers,
} from "./ManagedMemberSelection.js";
import {
  ManagedReaderFailure,
  uniqueManagedParseIssues,
  readManagedValue,
} from "./ManagedReaderFailure.js";
import { parseTypes, typeRanges } from "./ManagedMemberInspectorCore.js";
import {
  edges,
  parseFields,
  parseMemberRefs,
  parseMethods,
  referencedMemberNames,
} from "./ManagedMemberRows.js";

const unavailable = (
  target: BinaryTarget,
  bytes: Buffer,
  issue: ManagedParseIssue | null,
): ManagedMemberInspection =>
  managedMemberInspectionSchema.parse(
    admitManagedProjection({
      artifact: {
        path: target.path,
        sha256: target.sha256,
        byte_length: bytes.length,
        format: "pe",
      },
      module: null,
      metadata: {
        status:
          issue === null
            ? "absent"
            : issue.code === "resource-limit"
              ? "partial"
              : "malformed",
        version: null,
        table_row_counts: {},
      },
      identity_scope: {
        token_identity: "build-local",
        requires_artifact_sha256: target.sha256,
        requires_mvid: null,
      },
      types: [],
      fields: [],
      methods: [],
      member_refs: [],
      call_edges: [],
      field_accesses: [],
      coverage: {
        state: "unavailable",
        issues: issue === null ? [] : [issue],
      },
      limitations: [
        issue === null
          ? "The PE has no admitted CLI metadata; managed member inspection is unavailable."
          : "The CLI metadata could not be admitted; managed member inspection is unavailable.",
      ],
    }),
  );

const readMemberInventory = (
  bytes: Buffer,
  pe: ManagedPeLayout,
  issues: ManagedParseIssue[],
  scoped: boolean,
) => {
  const cli = pe.cli;
  if (cli === null)
    throw new TypeError("Managed inventory requires CLI metadata");
  const rootOffset = pe.rvaToOffset(
    cli.metadata.rva,
    cli.metadata.size,
    "cli.metadata",
  );
  const layout = readManagedMetadataLayout(
    bytes,
    rootOffset,
    cli.metadata.size,
  );
  if (scoped) {
    if ((layout.table(0)?.rowCount ?? 0) !== 1)
      issues.push({
        code: "invalid-row",
        scope: "metadata.Module",
        offset: layout.table(0)?.offset ?? null,
        detail: `Module table must contain exactly one row; found ${String(layout.table(0)?.rowCount ?? 0)}`,
      });
    const module =
      readManagedValue(
        () => readModule(bytes, layout, layout.strings.size),
        issues,
      ) ?? null;
    return { layout, inventory: { module, issues: [] } };
  }
  const inventory = readManagedMetadataInventory(
    bytes,
    layout,
    readManagedResourceDirectory(pe, issues),
  );
  return { layout, inventory };
};

/** Inspect metadata members and method bodies without loading target code. */
export const inspectManagedMembersBytes = (
  bytes: Buffer,
  target: BinaryTarget,
  options?: ManagedMemberSelectionOptions,
): ManagedMemberInspection => {
  const pe = readManagedPeLayout(bytes);
  if (pe.cli === null) return unavailable(target, bytes, pe.cliIssue);
  const issues: ManagedParseIssue[] = [];
  try {
    const { layout, inventory } = readMemberInventory(
      bytes,
      pe,
      issues,
      isScopedManagedSelection(options),
    );
    issues.push(...inventory.issues);
    const ranges = typeRanges(bytes, layout, issues);
    const selection = selectManagedMembers(ranges, layout, options);
    const parsedTypes = parseTypes(bytes, layout, ranges, selection.typeRows);
    issues.push(...parsedTypes.issues);
    const fields = parseFields(bytes, layout, ranges, selection.fieldRows);
    const methods = parseMethods({
      bytes,
      layout,
      pe,
      ranges,
      selectedRows: selection.methodRows,
      includeMethodBodies: selection.includeMethodBodies,
    });
    const referencedRows = selection.scoped
      ? referencedMemberRows(methods.methods, layout)
      : undefined;
    const memberRefs = parseMemberRefs(bytes, layout, referencedRows?.refs);
    issues.push(...memberRefs.issues);
    const referencedNames =
      referencedRows !== undefined
        ? referencedMemberNames(
            bytes,
            layout,
            {
              methods: referencedRows.methods.filter(
                (row) =>
                  !methods.core.has(`0x06${row.toString(16).padStart(6, "0")}`),
              ),
              fields: referencedRows.fields.filter(
                (row) =>
                  !fields.core.has(`0x04${row.toString(16).padStart(6, "0")}`),
              ),
            },
            issues,
          )
        : undefined;
    issues.push(...fields.issues, ...methods.issues);
    const coverageIssues = uniqueManagedParseIssues(issues);
    const incompleteMembers =
      [...fields.fields, ...memberRefs.refs, ...methods.methods].some(
        (member) => member.signature.parse_status !== "decoded",
      ) ||
      methods.methods.some(
        (method) =>
          method.body.status === "partial" ||
          method.body.status === "malformed",
      );
    const related = edges(
      methods.methods,
      referencedNames === undefined
        ? methods.core
        : new Map([...methods.core, ...referencedNames.methods]),
      referencedNames === undefined
        ? fields.core
        : new Map([...fields.core, ...referencedNames.fields]),
      memberRefs.core,
    );
    return managedMemberInspectionSchema.parse(
      admitManagedProjection(
        {
          artifact: {
            path: target.path,
            sha256: target.sha256,
            byte_length: bytes.length,
            format: "pe",
          },
          module: inventory.module,
          metadata: {
            status:
              issues.length === 0 && !selection.scoped ? "complete" : "partial",
            version: layout.version,
            table_row_counts: managedTableRowCounts(layout),
          },
          identity_scope: {
            token_identity: "build-local",
            requires_artifact_sha256: target.sha256,
            requires_mvid: inventory.module?.mvid ?? null,
          },
          types: parsedTypes.types,
          fields: fields.fields,
          methods: methods.methods,
          member_refs: memberRefs.refs,
          call_edges: related.callEdges,
          field_accesses: related.fieldAccesses,
          ...(selection.summary === undefined
            ? {}
            : {
                selection: {
                  ...selection.summary,
                  returned_types: parsedTypes.types.length,
                },
              }),
          coverage: {
            state:
              issues.length === 0 && !incompleteMembers && !selection.scoped
                ? "complete"
                : "partial",
            issues: coverageIssues,
          },
          limitations: [
            ...(selection.scoped
              ? [
                  "This inspection covers only the requested selection. Unselected members, references, attributes, resources, and omitted method bodies were not examined; missing results do not establish their absence.",
                ]
              : []),
            "Metadata tokens are build-local coordinates and are only meaningful with the reported artifact SHA-256 and MVID.",
            "CIL instruction anchors are decoded from file-backed method bodies only; no target assembly is loaded or executed.",
            "Signatures are decoded for common ECMA-335 primitive, class, valuetype, pointer, byref, array, and generic variable forms; unsupported forms retain raw signature hashes.",
          ],
        },
        managedDecodeBudget(layout),
      ),
    );
  } catch (cause: unknown) {
    if (cause instanceof ManagedReaderFailure)
      return unavailable(target, bytes, cause.issue);
    throw cause;
  }
};
