import { describe, expect, it } from "vitest";

import { inspectManagedMembersBytes } from "./ManagedMemberInspector.js";
import {
  buildManagedPeFixture,
  managedPeFixtureTarget,
} from "./ManagedPe.fixture.js";

const selectionFixture = (): Buffer =>
  buildManagedPeFixture({
    additionalTypes: [
      { name: "Second", methodName: "Run", ilBody: Buffer.from([0x06, 0x2a]) },
      { name: "Third", methodName: "Broken", ilBody: Buffer.from([0]) },
    ],
  });

describe("targeted managed member inspection", () => {
  it("paginates exact matching types in metadata token order and retains ownership ranges", () => {
    const bytes = selectionFixture();
    const result = inspectManagedMembersBytes(
      bytes,
      managedPeFixtureTarget(bytes),
      {
        type_names: ["Fixture.Third", "Fixture.Program", "Fixture.Second"],
        type_offset: 1,
        type_limit: 1,
      },
    );
    expect(result.types.map((type) => type.full_name)).toEqual([
      "Fixture.Second",
    ]);
    expect(result.types[0]?.method_list).toEqual({
      first_row: 2,
      last_row: 2,
      count: 1,
    });
    expect(result.fields).toEqual([]);
    expect(result.methods.map((method) => method.token)).toEqual([
      "0x06000002",
    ]);
    expect(result.methods[0]?.body.status).toBe("present");
    expect(result.member_refs).toEqual([]);
    expect(result.selection).toEqual({
      type_names: ["Fixture.Third", "Fixture.Program", "Fixture.Second"],
      method_tokens: [],
      include_method_bodies: true,
      type_offset: 1,
      type_limit: 1,
      total_matching_types: 3,
      returned_types: 1,
      next_type_offset: 2,
    });
    expect(result.coverage.state).toBe("partial");
  });

  it("intersects method tokens with type names and resolves only references used by selected bodies", () => {
    const bytes = selectionFixture();
    const target = managedPeFixtureTarget(bytes);
    const result = inspectManagedMembersBytes(bytes, target, {
      method_tokens: ["0x06000001"],
    });
    expect(result.types.map((type) => type.full_name)).toEqual([
      "Fixture.Program",
    ]);
    expect(result.methods.map((method) => method.token)).toEqual([
      "0x06000001",
    ]);
    expect(result.call_edges[0]?.target_name).toBe(".ctor");
    expect(result.field_accesses[0]?.field_name).toBe("counter");
    expect(result.member_refs.map((ref) => ref.token)).toEqual(["0x0a000001"]);
    const mismatch = inspectManagedMembersBytes(bytes, target, {
      type_names: ["Fixture.Second"],
      method_tokens: ["0x06000001"],
    });
    expect(mismatch.types).toEqual([]);
    expect(mismatch.methods).toEqual([]);
    expect(mismatch.selection?.total_matching_types).toBe(0);
    expect(mismatch.coverage.state).toBe("partial");
  });
});

describe("targeted managed member coverage", () => {
  it("leaves bodies explicitly unavailable during metadata-only inspection", () => {
    const bytes = selectionFixture();
    const result = inspectManagedMembersBytes(
      bytes,
      managedPeFixtureTarget(bytes),
      {
        include_method_bodies: false,
      },
    );
    expect(result.methods).toHaveLength(3);
    expect(
      result.methods.every((method) => method.body.status === "unavailable"),
    ).toBe(true);
    expect(result.methods[0]?.body).toMatchObject({
      issue: expect.stringContaining("not requested"),
      il_sha256: null,
      anchors: [],
    });
    expect(result.call_edges).toEqual([]);
    expect(result.coverage.state).toBe("partial");
  });

  it("reports an unknown match total when malformed type names cannot be matched", () => {
    const bytes = selectionFixture();
    const original = inspectManagedMembersBytes(
      bytes,
      managedPeFixtureTarget(bytes),
    );
    const third = original.types[2];
    if (third === undefined) throw new Error("Synthetic third type is missing");
    bytes.writeUInt16LE(0xffff, third.row_offset + 4);
    const result = inspectManagedMembersBytes(
      bytes,
      managedPeFixtureTarget(bytes),
      {
        type_names: ["Fixture.Program"],
      },
    );
    expect(result.types.map((type) => type.full_name)).toEqual([
      "Fixture.Program",
    ]);
    expect(result.selection?.total_matching_types).toBeNull();
    expect(result.coverage.state).toBe("partial");
    expect(result.coverage.issues.length).toBeGreaterThan(0);
  });

  it("names cross-type calls and field accesses without including or decoding the referenced method", () => {
    const il = Buffer.from([0x28, 1, 0, 0, 6, 0x7b, 1, 0, 0, 4, 0x2a]);
    const bytes = buildManagedPeFixture({
      ilBody: Buffer.from([0]),
      additionalTypes: [
        {
          name: "Caller",
          methodName: "Run",
          ilBody: Buffer.concat([Buffer.from([(il.length << 2) | 2]), il]),
        },
      ],
    });
    const result = inspectManagedMembersBytes(
      bytes,
      managedPeFixtureTarget(bytes),
      {
        type_names: ["Fixture.Caller"],
      },
    );
    expect(result.methods.map((method) => method.token)).toEqual([
      "0x06000002",
    ]);
    expect(result.fields).toEqual([]);
    expect(result.call_edges[0]?.target_name).toBe("Main");
    expect(result.field_accesses[0]?.field_name).toBe("counter");
    expect(result.coverage.issues).toEqual([]);
  });

  it("admits a targeted method when an unrelated body exceeds the retained decoding budget", () => {
    const largeBody = Buffer.alloc(300_012);
    largeBody.writeUInt16LE(0x3003, 0);
    largeBody.writeUInt16LE(8, 2);
    largeBody.writeUInt32LE(300_000, 4);
    largeBody[largeBody.length - 1] = 0x2a;
    const bytes = buildManagedPeFixture({
      additionalTypes: [
        { name: "Large", methodName: "LargeBody", ilBody: largeBody },
      ],
    });
    const target = managedPeFixtureTarget(bytes);
    expect(inspectManagedMembersBytes(bytes, target).coverage.issues).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: "resource-limit" }),
      ]),
    );
    const result = inspectManagedMembersBytes(bytes, target, {
      method_tokens: ["0x06000001"],
    });
    expect(result.methods).toHaveLength(1);
    expect(result.methods[0]?.body.status).toBe("present");
    expect(result.coverage.issues).toEqual([]);
  });
});
