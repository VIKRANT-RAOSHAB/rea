import { expect } from "vitest";

import { cliTest } from "../../support/cli/cliFixture.js";

cliTest.for([
  { spelling: "equals sign", targetArgs: ["--target="] },
  { spelling: "separate argument", targetArgs: ["--target", ""] },
])(
  "doctor rejects an explicitly empty target ($spelling) before filesystem admission",
  async ({ targetArgs }, { cli }) => {
    const result = await cli.run({
      arguments: ["doctor", ...targetArgs, "--json"],
    });

    expect(result.exitCode).toBe(1);
    expect(result.stderr).toBe("");
    expect(result.json).toMatchObject({
      code: "VALIDATION_ERROR",
      fieldErrors: [
        {
          path: "target",
          code: "too_small",
          message: "Target must not be empty",
        },
      ],
    });
  },
);

cliTest(
  "doctor keeps omitted target distinct from an explicit current-directory target",
  async ({ cli }) => {
    const omitted = await cli.run({ arguments: ["doctor", "--json"] });
    const omittedResponse = omitted.json as {
      scope?: { target?: string | null };
      scope_checks?: { name: string }[];
    };
    expect(omittedResponse.scope?.target).toBeNull();
    expect(
      omittedResponse.scope_checks?.some((check) => check.name === "target"),
    ).toBe(false);

    const dot = await cli.run({
      arguments: ["doctor", "--target=.", "--json"],
    });
    const dotResponse = dot.json as {
      scope?: { target?: string | null };
      scope_checks?: { name: string }[];
    };
    expect(dotResponse.scope?.target).toBe(".");
    expect(
      dotResponse.scope_checks?.some((check) => check.name === "target"),
    ).toBe(true);
  },
);
