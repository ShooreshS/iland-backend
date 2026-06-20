import authPolicy from "./policy";
import type { AuthChallengePurpose, AuthCredentialPlatform } from "../types/db";

type BuildCanonicalAuthChallengePayloadInput = {
  challengeId: string;
  challenge: string;
  purpose: AuthChallengePurpose;
  platform: AuthCredentialPlatform;
};

// Canonical signed payload for device credential authentication.
//
// Intention:
// - prevent ambiguous "just sign the raw nonce somehow" behavior across
//   platforms;
// - bind the signature to the issuer, challenge id, purpose, and platform;
// - keep one stable payload format that mobile and backend can test with golden
//   vectors later.
export const buildCanonicalAuthChallengePayload = (
  input: BuildCanonicalAuthChallengePayloadInput,
): string =>
  [
    "iland-auth-v1",
    `issuer:${authPolicy.issuer}`,
    `purpose:${input.purpose}`,
    `platform:${input.platform}`,
    `challenge_id:${input.challengeId}`,
    `challenge:${input.challenge}`,
  ].join("\n");

export default buildCanonicalAuthChallengePayload;
