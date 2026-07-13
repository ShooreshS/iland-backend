import { describe, expect, it } from "bun:test";

import { getZkpReleasePolicy } from "./zkpReleasePolicyService";

describe("zkpReleasePolicyService", () => {
  it("keeps current RC artifacts in ceremony-pending state", () => {
    const policy = getZkpReleasePolicy();

    expect(policy.version).toBe("civicos-zkp-release-policy-v1");
    expect(policy.publicDevnetVersion).toBe("0.1");
    expect(policy.mainnetMigrationVersion).toBe("0.1.1");
    expect(policy.humanCeremony.requiredBeforeMainnet).toBe(true);
    expect(policy.humanCeremony.minimumIndependentContributors).toBe(3);
    expect(policy.humanCeremony.status).toBe("pending_contributor_outputs");
    expect(policy.gates.finalArtifactsPinned).toBe(false);
    expect(policy.gates.mainnetV011Allowed).toBe(false);
    expect(policy.manifests.vote).toMatchObject({
      artifactKind: "vote",
      status: "loaded",
      circuitId: "civicos-groth16-vote-circuit-v1",
      publicInputSchemaVersion: "civicos-groth16-vote-public-inputs-v1",
      ceremony: "internal-release-candidate-single-contributor",
      contributionCount: 1,
      finalCeremonyArtifact: false,
    });
    expect(policy.manifests.tally).toMatchObject({
      artifactKind: "tally",
      status: "loaded",
      circuitId: "civicos-groth16-tally-circuit-v1",
      publicInputSchemaVersion: "civicos-groth16-tally-public-inputs-v1",
      ceremony: "internal-release-candidate-single-contributor",
      contributionCount: 1,
      finalCeremonyArtifact: false,
    });
  });
});
