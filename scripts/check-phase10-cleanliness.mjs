#!/usr/bin/env node

import { createClient } from "@supabase/supabase-js";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const backendRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const appRoot = resolve(backendRoot, "../iland");

const TRUE_VALUES = new Set(["1", "true", "yes"]);

const args = new Set(process.argv.slice(2));
const getArg = (name) => {
  const prefix = `${name}=`;
  const entry = process.argv.slice(2).find((arg) => arg.startsWith(prefix));
  return entry ? entry.slice(prefix.length) : null;
};
const expectEmptyOperationalDb =
  args.has("--expect-empty-operational") ||
  TRUE_VALUES.has(
    String(process.env.CIVICOS_PHASE10_EXPECT_EMPTY_OPERATIONAL_DB ?? "")
      .trim()
      .toLowerCase(),
  );
const defaultPreservedVerifiedIdentityIds = Object.freeze([
  "0ccf7dd6-9fbd-4eef-8952-29102f636422",
  "4ccdcda5-2e9c-4a68-ad2c-e98a6d728f45",
  "ffe5c615-b4a5-4b1e-885a-e7a818e72ec0",
]);
const preserveVerifiedIdentityIds = (
  getArg("--preserve-verified-identities") ||
  process.env.CIVICOS_PHASE10_PRESERVE_VERIFIED_IDENTITY_IDS ||
  (args.has("--expect-preserved-identities")
    ? defaultPreservedVerifiedIdentityIds.join(",")
    : "")
)
  .split(",")
  .map((entry) => entry.trim().toLowerCase())
  .filter(Boolean);
const expectPreservedIdentities =
  args.has("--expect-preserved-identities") ||
  preserveVerifiedIdentityIds.length > 0;

const loadDotEnvFile = (filePath) => {
  if (!existsSync(filePath)) {
    return;
  }

  const text = readFileSync(filePath, "utf8");
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) {
      continue;
    }

    const match = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line);
    if (!match) {
      continue;
    }

    const [, key, rawValue] = match;
    if (process.env[key] !== undefined) {
      continue;
    }

    let value = rawValue.trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    process.env[key] = value;
  }
};

loadDotEnvFile(resolve(backendRoot, ".env"));

const blockers = [];
const warnings = [];
const checks = [];

const record = (ok, label, details = undefined) => {
  checks.push({ ok, label, ...(details === undefined ? {} : { details }) });
  if (!ok) {
    blockers.push(label);
  }
};

const warn = (label, details = undefined) => {
  warnings.push(label);
  checks.push({
    ok: true,
    warning: true,
    label,
    ...(details === undefined ? {} : { details }),
  });
};

const supabaseUrl = process.env.SUPABASE_URL;
const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

record(
  typeof supabaseUrl === "string" && supabaseUrl.startsWith("https://"),
  "SUPABASE_URL is configured",
);
record(
  typeof serviceRoleKey === "string" && serviceRoleKey.length > 20,
  "SUPABASE_SERVICE_ROLE_KEY is configured",
);

const countRows = async (supabase, spec) => {
  let query = supabase
    .from(spec.table)
    .select(spec.selectColumn ?? "id", { count: "exact", head: true });

  for (const filter of spec.filters ?? []) {
    switch (filter.op) {
      case "eq":
        query = query.eq(filter.column, filter.value);
        break;
      case "neq":
        query = query.neq(filter.column, filter.value);
        break;
      case "like":
        query = query.like(filter.column, filter.value);
        break;
      case "in":
        query = query.in(filter.column, filter.value);
        break;
      case "not.in":
        query = query.not(filter.column, "in", `(${filter.value.join(",")})`);
        break;
      case "is":
        query = query.is(filter.column, filter.value);
        break;
      case "not.is":
        query = query.not(filter.column, "is", filter.value);
        break;
      default:
        throw new Error(`Unsupported filter op: ${filter.op}`);
    }
  }

  const { count, error } = await query;
  if (error) {
    throw new Error(`${spec.table}: ${error.message}`);
  }

  return count ?? 0;
};

const listRows = async (supabase, spec) => {
  let query = supabase.from(spec.table).select(spec.select ?? "*");
  for (const filter of spec.filters ?? []) {
    switch (filter.op) {
      case "in":
        query = query.in(filter.column, filter.value);
        break;
      case "eq":
        query = query.eq(filter.column, filter.value);
        break;
      default:
        throw new Error(`Unsupported list filter op: ${filter.op}`);
    }
  }
  const { data, error } = await query;
  if (error) {
    throw new Error(`${spec.table}: ${error.message}`);
  }
  return data || [];
};

const forbiddenMarkers = Object.freeze([
  {
    label: "synthetic ZKP seed users by username",
    table: "users",
    filters: [{ op: "like", column: "username", value: "zkp-seed-%" }],
  },
  {
    label: "synthetic ZKP seed users by display name",
    table: "users",
    filters: [
      { op: "eq", column: "display_name", value: "CivicOS ZKP seed voter" },
    ],
  },
  {
    label: "synthetic ZKP seed verified identities",
    table: "verified_identities",
    filters: [
      { op: "eq", column: "verification_method", value: "civicos_zkp_seed" },
    ],
  },
  {
    label: "mock identity profiles",
    table: "identity_profiles",
    filters: [{ op: "eq", column: "home_location_source", value: "mock" }],
  },
  {
    label: "synthetic ZKP seed credential registry rows",
    table: "credential_registry",
    filters: [
      {
        op: "eq",
        column: "credential_issuer_id",
        value: "did:iland:backend:zkp-seed-v1",
      },
    ],
  },
  {
    label: "legacy or pre-prover polls",
    table: "polls",
    filters: [
      {
        op: "in",
        column: "vote_privacy_mode",
        value: ["legacy_identity_linked", "zk_preprover_audit"],
      },
    ],
  },
  {
    label: "polls missing frozen policy hash",
    table: "polls",
    filters: [{ op: "is", column: "poll_policy_hash", value: null }],
  },
  {
    label: "legacy identity-linked vote rows",
    table: "votes",
  },
]);

const operationalTables = Object.freeze([
  ["users", "id"],
  ["identity_profiles", "id"],
  ["verified_identities", "id"],
  ["wallet_credentials", "id"],
  ["auth_credentials", "id"],
  ["app_attestation_credentials", "id"],
  ["auth_sessions", "id"],
  ["refresh_token_families", "id"],
  ["auth_challenges", "id"],
  ["auth_audit_events", "id"],
  ["polls", "id"],
  ["poll_options", "id"],
  ["votes", "id"],
  ["poll_zk_votes", "id"],
  ["poll_tally_proofs", "id"],
  ["poll_roots", "id"],
  ["poll_audit_events", "id"],
  ["poll_encryption_keys", "id"],
  ["poll_map_marker_cache", "poll_id"],
  ["poll_map_refresh_queue", "poll_id"],
  ["credential_registry", "id"],
  ["credential_roots", "id"],
  ["oidc_access_tokens", "id"],
  ["oidc_authorize_qr_transactions", "id"],
  ["oidc_authorization_requests", "id"],
  ["oidc_authorization_codes", "id"],
  ["oidc_grants", "id"],
  ["oidc_pairwise_subjects", "id"],
  ["oidc_refresh_token_families", "id"],
  ["oidc_audit_events", "id"],
  ["backend_audit_events", "id"],
]);

const readEnvAssignments = (filePath) => {
  if (!existsSync(filePath)) {
    return new Map();
  }

  const entries = new Map();
  const text = readFileSync(filePath, "utf8");
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) {
      continue;
    }

    const match = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line);
    if (!match) {
      continue;
    }

    let value = match[2].trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    entries.set(match[1], value);
  }

  return entries;
};

const isTruthyEnv = (entries, key) =>
  TRUE_VALUES.has(String(entries.get(key) ?? "").trim().toLowerCase());

const appEnv = readEnvAssignments(resolve(appRoot, ".env"));
for (const key of [
  "EXPO_PUBLIC_ENABLE_IDENTITY_DEBUG_PANEL",
  "EXPO_PUBLIC_ENABLE_IDENTITY_MOCK_TOOLS",
  "EXPO_PUBLIC_ENABLE_LEGACY_MOCK_VIEWER_FALLBACK",
  "EXPO_PUBLIC_ENABLE_DEV_LEGACY_VOTE_FALLBACK",
]) {
  record(!isTruthyEnv(appEnv, key), `public app .env does not enable ${key}`);
}

const appLocalEnv = readEnvAssignments(resolve(appRoot, ".env.local"));
for (const key of [
  "EXPO_PUBLIC_ENABLE_IDENTITY_DEBUG_PANEL",
  "EXPO_PUBLIC_ENABLE_IDENTITY_MOCK_TOOLS",
  "EXPO_PUBLIC_ENABLE_LEGACY_MOCK_VIEWER_FALLBACK",
  "EXPO_PUBLIC_ENABLE_DEV_LEGACY_VOTE_FALLBACK",
]) {
  if (isTruthyEnv(appLocalEnv, key)) {
    warn(`local app .env.local enables ${key}; keep it out of release builds`);
  }
}

if (supabaseUrl && serviceRoleKey) {
  const supabase = createClient(supabaseUrl, serviceRoleKey, {
    auth: { autoRefreshToken: false, persistSession: false },
    global: { headers: { "X-Client-Info": "iland-phase10-cleanliness" } },
  });

  const markerCounts = {};
  for (const marker of forbiddenMarkers) {
    try {
      const count = await countRows(supabase, marker);
      markerCounts[marker.label] = count;
      record(
        count === 0,
        `no ${marker.label}`,
        count === 0 ? undefined : { count },
      );
    } catch (error) {
      record(false, `count query failed for ${marker.label}`, {
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }

  const operationalCounts = {};
  for (const [table, selectColumn] of operationalTables) {
    try {
      operationalCounts[table] = await countRows(supabase, {
        table,
        selectColumn,
      });
    } catch (error) {
      record(false, `count query failed for table ${table}`, {
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }

  if (expectPreservedIdentities) {
    if (preserveVerifiedIdentityIds.length !== 3) {
      record(false, "Phase 10 preserve set contains exactly 3 verified identity ids", {
        count: preserveVerifiedIdentityIds.length,
      });
    }

    try {
      const preservedIdentities = await listRows(supabase, {
        table: "verified_identities",
        select: "id,user_id,verification_method",
        filters: [
          {
            op: "in",
            column: "id",
            value: preserveVerifiedIdentityIds,
          },
        ],
      });
      const preservedUserIds = preservedIdentities.map((row) => row.user_id);
      record(
        preservedIdentities.length === 3 &&
          preservedIdentities.every(
            (row) => row.verification_method === "passport_nfc",
          ),
        "preserved identities exist and are passport_nfc",
        preservedIdentities.map((row) => ({
          id: row.id,
          userId: row.user_id,
          verificationMethod: row.verification_method,
        })),
      );

      const preservedUserCount = preservedUserIds.length;
      const allowedByUserTable = [
        "users",
        "identity_profiles",
        "wallet_credentials",
        "auth_credentials",
        "app_attestation_credentials",
        "auth_sessions",
        "refresh_token_families",
      ];
      for (const table of allowedByUserTable) {
        const unexpected = await countRows(supabase, {
          table,
          filters: [
            {
              op: "not.in",
              column: table === "users" ? "id" : "user_id",
              value: preservedUserIds,
            },
          ],
        });
        record(unexpected === 0, `no non-preserved rows in ${table}`, {
          unexpected,
        });
      }
      record(
        (operationalCounts.users ?? -1) === preservedUserCount,
        "only preserved users remain",
        { count: operationalCounts.users, expected: preservedUserCount },
      );
      record(
        (operationalCounts.verified_identities ?? -1) === 3,
        "only preserved verified identities remain",
        { count: operationalCounts.verified_identities, expected: 3 },
      );

      const nonPreservedRegistry = await countRows(supabase, {
        table: "credential_registry",
        filters: [
          {
            op: "not.in",
            column: "verified_identity_id",
            value: preserveVerifiedIdentityIds,
          },
        ],
      });
      record(
        nonPreservedRegistry === 0,
        "no non-preserved credential registry rows remain",
        { unexpected: nonPreservedRegistry },
      );

      for (const table of [
        "polls",
        "poll_options",
        "votes",
        "poll_zk_votes",
        "poll_tally_proofs",
        "poll_roots",
        "poll_audit_events",
        "poll_encryption_keys",
        "poll_map_marker_cache",
        "poll_map_refresh_queue",
        "credential_roots",
        "oidc_access_tokens",
        "oidc_authorize_qr_transactions",
        "oidc_authorization_requests",
        "oidc_authorization_codes",
        "oidc_grants",
        "oidc_pairwise_subjects",
        "oidc_refresh_token_families",
        "oidc_audit_events",
        "backend_audit_events",
      ]) {
        record((operationalCounts[table] ?? -1) === 0, `${table} is empty`, {
          count: operationalCounts[table],
        });
      }
    } catch (error) {
      record(false, "preserved identity verification query failed", {
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }

  const nonEmptyOperationalTables = Object.entries(operationalCounts)
    .filter(([, count]) => count > 0)
    .sort(([a], [b]) => a.localeCompare(b));

  if (expectEmptyOperationalDb && !expectPreservedIdentities) {
    for (const [table, count] of nonEmptyOperationalTables) {
      record(false, `operational table is empty: ${table}`, { count });
    }
  } else if (!expectPreservedIdentities && nonEmptyOperationalTables.length > 0) {
    warn(
      "operational DB is not empty; pass --expect-empty-operational for the public-launch cleanup gate",
      Object.fromEntries(nonEmptyOperationalTables),
    );
  }
}

const report = {
  status: blockers.length === 0 ? "clean" : "blocked",
  mode: expectEmptyOperationalDb
    ? "public_launch_empty_operational_db"
    : expectPreservedIdentities
      ? "public_launch_preserve_verified_identities"
    : "forbidden_debug_marker_scan",
  destructive: false,
  checkedAt: new Date().toISOString(),
  checks,
  warnings,
  blockers,
};

console.log(JSON.stringify(report, null, 2));
process.exit(blockers.length === 0 ? 0 : 1);
