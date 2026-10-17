import { describe, expect, it } from "vitest";

import {
  FOREIGN_EXECUTION_TOOL_NAMES,
  refusesUnderStrictContainment,
} from "./foreignExecutionTools.js";
import { TOOL_CONTRACTS } from "./toolContracts.js";

describe("foreign-execution tool set", () => {
  it("names exactly the tools that run foreign code or change a device", () => {
    // Pinned so a new execute-capable tool must be considered for containment.
    expect([...FOREIGN_EXECUTION_TOOL_NAMES].sort()).toEqual([
      "capture_browser_scenario",
      "capture_electron_scenario",
      "capture_native_ui_scenario",
      "capture_process_scenario",
      "install_adb_package",
      "observe_native_calls",
      "push_adb_file",
      "start_adb_activity",
      "start_adb_app",
      "stop_adb_app",
      "uninstall_adb_package",
    ]);
  });

  it("stays derived from the declared effects", () => {
    for (const contract of TOOL_CONTRACTS)
      expect(refusesUnderStrictContainment(contract.name)).toBe(
        contract.effects.executesForeignCode || contract.effects.mutatesDevice,
      );
  });

  it("never gates a malware-provider tool, which only reads or emulates", () => {
    const gatedMalware = TOOL_CONTRACTS.filter(
      (contract) =>
        contract.kind === "malware-provider" &&
        refusesUnderStrictContainment(contract.name),
    );
    expect(gatedMalware).toEqual([]);
  });
});
