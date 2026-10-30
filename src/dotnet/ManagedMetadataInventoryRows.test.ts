import { describe, expect, it } from "vitest";

import { buildManagedPeFixture } from "./ManagedPe.fixture.js";
import { readCustomAttribute } from "./ManagedMetadataInventoryRows.js";
import {
  metadataRowOffset,
  readManagedMetadataLayout,
  type ManagedMetadataLayout,
} from "./ManagedMetadataLayout.js";
import { readManagedPeLayout } from "./ManagedPeReader.js";
import { ManagedReaderFailure } from "./ManagedReaderFailure.js";

describe("custom attribute constructor ownership", () => {
  it("resolves repeated local constructors without repeatedly scanning the type table", () => {
    const bytes = buildManagedPeFixture({
      customAttributeTypeRaw: (1001 << 3) | 2,
      additionalTypes: Array.from({ length: 1000 }, (_, index) => ({
        name: `Attribute${index}`,
        methodName: ".ctor",
        ilBody: Buffer.from([0x06, 0x2a]),
      })),
    });
    const pe = readManagedPeLayout(bytes);
    if (pe.cli === null) throw new Error("fixture omitted CLI metadata");
    const layout = readManagedMetadataLayout(
      bytes,
      pe.rvaToOffset(pe.cli.metadata.rva, pe.cli.metadata.size, "cli.metadata"),
      pe.cli.metadata.size,
    );
    const heapExtent = Math.max(layout.strings.size, layout.blob.size);
    const attributes = Array.from({ length: 500 }, () =>
      readCustomAttribute(bytes, layout, 1, heapExtent),
    );
    expect(attributes).toHaveLength(500);
    expect(
      attributes.every(
        (attribute) => attribute.type_name === "Fixture.Attribute999",
      ),
    ).toBe(true);
  });

  it.each([
    { starts: [1, 1, 3], method: 1, owner: "Second" },
    { starts: [1, 1, 3], method: 2, owner: "Second" },
    { starts: [1, 2, 2], method: 2, owner: "Third" },
    { starts: [1, 4, 4], method: 3, owner: "Program" },
  ])(
    "skips empty types when locating constructor ownership: %j",
    ({ starts, method, owner }) => {
      const bytes = buildManagedPeFixture({
        customAttributeTypeRaw: (method << 3) | 2,
        additionalTypes: [
          {
            name: "Second",
            methodName: ".ctor",
            ilBody: Buffer.from([0x06, 0x2a]),
          },
          {
            name: "Third",
            methodName: ".ctor",
            ilBody: Buffer.from([0x06, 0x2a]),
          },
        ],
      });
      const layout = layoutFor(bytes);
      starts.forEach((start, index) =>
        writeMethodStart(bytes, layout, index + 1, start),
      );
      expect(
        readCustomAttribute(bytes, layout, 1, heapExtent(layout)),
      ).toMatchObject({
        constructor_token: `0x06${method.toString(16).padStart(6, "0")}`,
        type_name: `Fixture.${owner}`,
      });
    },
  );

  it.each([
    { row: 1, start: 0 },
    { row: 3, start: 1 },
    { row: 3, start: 5 },
  ])(
    "rejects malformed ownership ranges at the offending TypeDef: %j",
    ({ row, start }) => {
      const bytes = buildManagedPeFixture({
        customAttributeTypeRaw: (1 << 3) | 2,
        additionalTypes: [
          {
            name: "Second",
            methodName: ".ctor",
            ilBody: Buffer.from([0x06, 0x2a]),
          },
          {
            name: "Third",
            methodName: ".ctor",
            ilBody: Buffer.from([0x06, 0x2a]),
          },
        ],
      });
      const layout = layoutFor(bytes);
      writeMethodStart(bytes, layout, row, start);
      const failure = constructorFailure(bytes, layout);
      expect(failure.issue).toMatchObject({
        code: "invalid-row",
        scope: `metadata.TypeDef:0x02${row.toString(16).padStart(6, "0")}`,
        offset: metadataRowOffset(layout, 2, row),
      });
    },
  );

  it("retains a malformed ownership diagnosis across repeated constructor lookups", () => {
    const bytes = buildManagedPeFixture({
      customAttributeTypeRaw: (1 << 3) | 2,
      additionalTypes: Array.from({ length: 1000 }, (_, index) => ({
        name: `Attribute${index}`,
        methodName: ".ctor",
        ilBody: Buffer.from([0x06, 0x2a]),
      })),
    });
    const layout = layoutFor(bytes);
    writeMethodStart(bytes, layout, 1001, 0);
    for (let lookup = 0; lookup < 500; lookup += 1)
      expect(constructorFailure(bytes, layout).issue).toMatchObject({
        code: "invalid-row",
        scope: "metadata.TypeDef:0x020003e9",
      });
  });
});

const layoutFor = (bytes: Buffer): ManagedMetadataLayout => {
  const pe = readManagedPeLayout(bytes);
  if (pe.cli === null) throw new Error("fixture omitted CLI metadata");
  return readManagedMetadataLayout(
    bytes,
    pe.rvaToOffset(pe.cli.metadata.rva, pe.cli.metadata.size, "cli.metadata"),
    pe.cli.metadata.size,
  );
};

const heapExtent = (layout: ManagedMetadataLayout): number =>
  Math.max(layout.strings.size, layout.blob.size);

const writeMethodStart = (
  bytes: Buffer,
  layout: ManagedMetadataLayout,
  row: number,
  start: number,
): void => {
  const types = layout.table(2);
  if (types === undefined) throw new Error("fixture omitted TypeDef table");
  const width = layout.tableIndexSize(6);
  const offset = metadataRowOffset(layout, 2, row) + types.rowSize - width;
  if (width === 2) bytes.writeUInt16LE(start, offset);
  else bytes.writeUInt32LE(start, offset);
};

const constructorFailure = (
  bytes: Buffer,
  layout: ManagedMetadataLayout,
): ManagedReaderFailure => {
  try {
    readCustomAttribute(bytes, layout, 1, heapExtent(layout));
  } catch (cause: unknown) {
    if (cause instanceof ManagedReaderFailure) return cause;
    throw cause;
  }
  throw new Error("Expected malformed method ownership to fail");
};
