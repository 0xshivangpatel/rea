import { z } from "zod";

import { ConfigurationError } from "../domain/configurationErrors.js";
import { err, ok, type Result } from "../domain/result.js";

/**
 * Operator-declared containment posture for analyzing untrusted samples.
 *
 * REA cannot configure the host firewall; this records the operator's
 * assertion about the lab's egress and gates tools whose foreign code could
 * reach the network. The split an analyst needs — the agent's model API stays
 * reachable while the sample's egress does not — is enforced at the network
 * layer (an isolated detonation host, host-only NIC, a default-deny firewall
 * with an allowlist to the model API, and a simulator for the sample). This
 * policy makes that posture explicit and refuses execution REA cannot assume
 * is contained.
 */
export const UNTRUSTED_EXECUTION_MODES = [
  "isolated",
  "simulated",
  "strict",
] as const;

export type UntrustedExecutionMode = (typeof UNTRUSTED_EXECUTION_MODES)[number];

/** How the operator declared the sample host's egress is constrained. */
export type SampleNetworkPosture = "undeclared" | "denied" | "simulated";

/** Parsed containment posture consumed by the server and malware workflows. */
export interface UntrustedExecutionPolicy {
  /** Null when the variable is unset: permissive, today's behavior. */
  readonly mode: UntrustedExecutionMode | null;
  /**
   * False only in strict mode, where tools whose contract declares
   * `executesForeignCode` or `mutatesDevice` refuse before launching.
   */
  readonly executionPermitted: boolean;
  readonly sampleNetwork: SampleNetworkPosture;
}

/** The default when `REA_UNTRUSTED_EXECUTION` is unset. */
export const PERMISSIVE_EXECUTION_POLICY: UntrustedExecutionPolicy = {
  mode: null,
  executionPermitted: true,
  sampleNetwork: "undeclared",
};

const schema = z.enum(UNTRUSTED_EXECUTION_MODES);

const constraint =
  'REA_UNTRUSTED_EXECUTION must be "isolated" (host isolated, sample egress denied at the network layer), "simulated" (sample egress answered by a simulator such as INetSim or FakeNet-NG), or "strict" (refuse every tool whose foreign code could reach the network). Unset leaves execution permissive for ordinary reverse engineering. REA does not configure the firewall; it records this posture and gates accordingly.';

const policyFor = (mode: UntrustedExecutionMode): UntrustedExecutionPolicy => ({
  mode,
  executionPermitted: mode !== "strict",
  sampleNetwork:
    mode === "simulated"
      ? "simulated"
      : mode === "isolated"
        ? "denied"
        : "undeclared",
});

/** Parse the declared containment posture; unset is permissive. */
export const parseUntrustedExecutionPolicy = (
  value: string | undefined,
): Result<UntrustedExecutionPolicy, ConfigurationError> => {
  if (value === undefined || value === "")
    return ok(PERMISSIVE_EXECUTION_POLICY);
  const parsed = schema.safeParse(value);
  return parsed.success
    ? ok(policyFor(parsed.data))
    : err(
        new ConfigurationError(constraint, {
          settings: [{ setting: "REA_UNTRUSTED_EXECUTION", constraint }],
        }),
      );
};
