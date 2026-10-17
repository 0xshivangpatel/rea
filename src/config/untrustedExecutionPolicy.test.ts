import { describe, expect, it } from "vitest";

import { ConfigurationError } from "../domain/configurationErrors.js";
import {
  PERMISSIVE_EXECUTION_POLICY,
  parseUntrustedExecutionPolicy,
} from "./untrustedExecutionPolicy.js";

const value = (input: string | undefined) => {
  const parsed = parseUntrustedExecutionPolicy(input);
  if (!parsed.ok) throw parsed.error;
  return parsed.value;
};

describe("untrusted execution policy", () => {
  it("is permissive and undeclared when unset or empty", () => {
    expect(value(undefined)).toEqual(PERMISSIVE_EXECUTION_POLICY);
    expect(value("")).toEqual(PERMISSIVE_EXECUTION_POLICY);
    expect(PERMISSIVE_EXECUTION_POLICY).toMatchObject({
      mode: null,
      executionPermitted: true,
      sampleNetwork: "undeclared",
    });
  });

  it("maps each declared mode to its execution and network posture", () => {
    expect(value("isolated")).toEqual({
      mode: "isolated",
      executionPermitted: true,
      sampleNetwork: "denied",
    });
    expect(value("simulated")).toEqual({
      mode: "simulated",
      executionPermitted: true,
      sampleNetwork: "simulated",
    });
    expect(value("strict")).toEqual({
      mode: "strict",
      executionPermitted: false,
      sampleNetwork: "undeclared",
    });
  });

  it("rejects an unknown value with an actionable configuration error", () => {
    const parsed = parseUntrustedExecutionPolicy("sandbox");
    if (parsed.ok) throw new Error("Expected an invalid value to be rejected");
    expect(parsed.error).toBeInstanceOf(ConfigurationError);
    expect(parsed.error.settings).toEqual([
      {
        setting: "REA_UNTRUSTED_EXECUTION",
        constraint: expect.stringContaining("isolated"),
      },
    ]);
  });
});
