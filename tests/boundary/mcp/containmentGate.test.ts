import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { expect, it, onTestFinished } from "vitest";

import { createAnalysisExecution } from "../../../src/application/AnalysisProvider.js";
import type { MalwareAnalysisPort } from "../../../src/application/malware/MalwareAnalysisPort.js";
import { ok } from "../../../src/domain/result.js";
import { createServer } from "../../../src/server/createServer.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";

const sha256 =
  "9f63a60f84528acbc6994c93d9acddf194045231399d2e39e7f0e58bec7b45f8";

// A malware port that answers inspect_packet_capture, to show static/artifact
// tools still run under the strict policy.
const malwarePort: MalwareAnalysisPort = {
  async close() {},
  async execute(request) {
    if (request.operation !== "inspect_packet_capture")
      throw new Error(`Unexpected operation ${request.operation}`);
    return ok(
      createAnalysisExecution(
        {
          tool: {
            name: "TShark",
            version: "4.2.2",
            command: "tshark",
            command_source: "path",
          },
          capture: { path: request.input.path, bytes: 64, sha256 },
          display_filter: null,
          packets_examined: 0,
          first_time: null,
          last_time: null,
          dns: [],
          http_requests: [],
          tls_client_hellos: [],
          connections: [],
        },
        { id: "tshark", name: "TShark", version: "4.2.2" },
        { subject: { path: request.input.path, sha256, format: "file" } },
      ),
    );
  },
};

const text = (response: Awaited<ReturnType<Client["callTool"]>>) =>
  (response.content as { readonly text?: string }[])
    .map((part) => part.text ?? "")
    .join("");

const connect = async (environment: Record<string, string>) => {
  const session = createTestBinarySession(() => {
    throw new Error("must not acquire a native provider");
  });
  const server = createServer(
    { kind: "session", session },
    { malwareAnalysis: malwarePort, environment },
  );
  const client = new Client({ name: "containment", version: "1" });
  onTestFinished(async () => {
    await client.close();
    await server.close();
    await session.close();
  });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  return client;
};

// stop_adb_app declares mutatesDevice, so it is in the strict-mode refusal set.
const deviceToolArgs = {
  name: "stop_adb_app",
  arguments: { serial: "emulator-5554", package: "com.example.app" },
} as const;

it("refuses a device-mutating tool before launch under strict containment", async () => {
  const client = await connect({ REA_UNTRUSTED_EXECUTION: "strict" });
  const response = await client.callTool(deviceToolArgs);
  expect(response.isError).toBe(true);
  expect(text(response)).toMatch(/REA_UNTRUSTED_EXECUTION/u);
  // A static/artifact malware tool still runs: it cannot reach the network.
  const capture = await client.callTool({
    name: "inspect_packet_capture",
    arguments: { path: "/cases/run.pcap" },
  });
  expect(capture.isError, text(capture)).not.toBe(true);
});

it("does not apply the containment refusal when the policy is unset", async () => {
  const client = await connect({});
  const response = await client.callTool(deviceToolArgs);
  // The tool may still fail (no adb configured), but never with the gate.
  expect(text(response)).not.toMatch(/REA_UNTRUSTED_EXECUTION/u);
});
