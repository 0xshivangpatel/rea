import { TOOL_CONTRACTS } from "./toolContracts.js";

/**
 * Tools whose contract declares that it runs code REA does not own — the
 * analysis target or a caller-selected executable — or changes an attached
 * device. These are the operations whose foreign code could reach the network,
 * so the strict containment policy refuses them. Derived from the effect audit
 * so the set never drifts from the declared effects.
 */
export const FOREIGN_EXECUTION_TOOL_NAMES: ReadonlySet<string> = new Set(
  TOOL_CONTRACTS.filter(
    (contract) =>
      contract.effects.executesForeignCode || contract.effects.mutatesDevice,
  ).map((contract) => contract.name),
);

/** True when the strict containment policy must refuse this tool before launch. */
export const refusesUnderStrictContainment = (name: string): boolean =>
  FOREIGN_EXECUTION_TOOL_NAMES.has(name);
