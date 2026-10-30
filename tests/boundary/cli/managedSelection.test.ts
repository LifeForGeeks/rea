import { Cli } from "incur";
import { expect, it } from "vitest";

import { registerManagedCommands } from "../../../src/cli/managedCommands.js";
import { silentLogger } from "../../../src/logger.js";

it("preserves explicit managed member selectors through CLI option parsing", async () => {
  const cli = Cli.create("rea-managed-selection", { sync: false });
  const calls: unknown[] = [];
  registerManagedCommands(
    cli,
    silentLogger,
    async (path, operation, parameters) => {
      calls.push({ path, operation, parameters });
      return {};
    },
  );
  let exitCode = 0;
  await cli.serve(
    [
      "inspect-managed-members",
      "fixture.dll",
      "--type-names",
      "Fixture.Program",
      "--type-names",
      "Other.Type",
      "--method-tokens",
      "0x06000001",
      "--include-method-bodies=false",
      "--type-offset",
      "0",
      "--type-limit",
      "1",
      "--json",
    ],
    {
      stdout: () => undefined,
      exit: (code) => {
        exitCode = code;
      },
    },
  );
  expect(exitCode).toBe(0);
  expect(calls).toEqual([
    {
      path: "fixture.dll",
      operation: "inspect_managed_members",
      parameters: {
        type_names: ["Fixture.Program", "Other.Type"],
        method_tokens: ["0x06000001"],
        include_method_bodies: false,
        type_offset: 0,
        type_limit: 1,
      },
    },
  ]);
});

it("leaves the managed member request unscoped when CLI options are omitted", async () => {
  const cli = Cli.create("rea-managed-default", { sync: false });
  const calls: unknown[] = [];
  registerManagedCommands(
    cli,
    silentLogger,
    async (_path, _operation, parameters) => {
      calls.push(parameters);
      return {};
    },
  );
  await cli.serve(["inspect-managed-members", "fixture.dll", "--json"], {
    stdout: () => undefined,
    exit: () => undefined,
  });
  expect(calls).toEqual([{}]);
});

it.each([
  ["--type-limit", "0"],
  ["--type-offset", "-1"],
  ["--type-limit", "9007199254740992"],
  ["--method-tokens", "0x02000001"],
  ["--type-names", ""],
])(
  "rejects invalid managed CLI selection %s %s before analysis",
  async (flag, value) => {
    const cli = Cli.create("rea-managed-invalid", { sync: false });
    let calls = 0;
    let exitCode = 0;
    registerManagedCommands(cli, silentLogger, async () => {
      calls += 1;
      return {};
    });
    await cli.serve(
      ["inspect-managed-members", "fixture.dll", flag, value, "--json"],
      {
        stdout: () => undefined,
        exit: (code) => {
          exitCode = code;
        },
      },
    );
    expect(exitCode).toBe(1);
    expect(calls).toBe(0);
  },
);
