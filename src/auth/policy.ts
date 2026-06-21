import env from "../config/env";

// Central auth policy constants.
//
// Intention:
// - keep the production trust boundary explicit in one place;
// - make it easy to read which decisions are hard policy versus temporary
//   compatibility seams;
// - ensure future auth/session code and OIDC code share the same issuer and
//   session rules.
export const authPolicy = Object.freeze({
  issuer: env.auth.issuer,
  accessTokenTtlSeconds: env.auth.accessTokenTtlSeconds,
  refreshTokenTtlDays: env.auth.refreshTokenTtlDays,
  maxActiveSessionsPerUser: env.auth.maxActiveSessionsPerUser,
  // Production policy: every protected route must be backed by an attested app
  // session.
  requireAttestedSessionsForProtectedRoutes:
    env.auth.requireAttestedSessionsForProtectedRoutes,
  // Transitional implementation seam:
  // non-production environments may temporarily bypass full device-key and app
  // attestation cryptographic verification so the backend contract and mobile
  // integration can be built incrementally. This must remain disabled in
  // production.
  enableTransitionalCryptoBypass: env.auth.enableTransitionalCryptoBypass,
  iosTeamId: env.auth.iosTeamId,
  iosBundleId: env.auth.iosBundleId,
  androidPackageName: env.auth.androidPackageName,
  iosAppAttestEnvironment: env.auth.iosAppAttestEnvironment,
  androidAllowedSigningCertDigests: env.auth.androidAllowedSigningCertDigests,
  androidGoogleApiKey: env.auth.androidGoogleApiKey,
  androidRequireStrongIntegrity: env.auth.androidRequireStrongIntegrity,
});

export default authPolicy;
