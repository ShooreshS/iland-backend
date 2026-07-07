export const SOLANA_AUDIT_CLUSTERS = [
  "localnet",
  "devnet",
  "testnet",
  "mainnet-beta",
] as const;

export type SolanaAuditCluster = (typeof SOLANA_AUDIT_CLUSTERS)[number];

export const SOLANA_AUDIT_FEE_MODES = [
  "civicos-sponsored",
  "user-paid",
] as const;

export type SolanaAuditFeeMode = (typeof SOLANA_AUDIT_FEE_MODES)[number];

export const DEFAULT_SOLANA_AUDIT_FEE_MODE: SolanaAuditFeeMode =
  "civicos-sponsored";

export const SOLANA_BASE_FEE_LAMPORTS_PER_SIGNATURE = 5_000;

export const CIVICOS_AUDIT_PROGRAM_ID =
  "FsXuodQtkWjE1EZEAUskvRuj4bGMrKZAHAEf4WEk4oRo" as const;

export const TOKEN_2022_PROGRAM_ID =
  "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb" as const;

export const SHOLAN_TOKEN_DEFAULTS = Object.freeze({
  cluster: "mainnet-beta" as const,
  mint: "GJRpZhWZcLGP8ZUKggxDTw7y5N3LGXa2gWqKRSLDWiBq",
  tokenProgram: TOKEN_2022_PROGRAM_ID,
  name: "Sholan token",
  symbol: "SHOLAN",
  decimals: 9,
  supplyBaseUnits: "9999111000000000000",
  supplyUiAmount: "9999111000",
  metadataUri:
    "https://raw.githubusercontent.com/ShooreshS/shooresh-token/main/sholan-metadata.json",
  metadataUpdateAuthority: "4eDFMXLgNxSLstBG2F6wx8w3hiMy753u4bxPnSK1Ghcm",
  mintAuthority: null,
  freezeAuthority: null,
});
