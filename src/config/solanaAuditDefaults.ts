export const SOLANA_AUDIT_CLUSTERS = [
  "localnet",
  "devnet",
  "testnet",
  "mainnet-beta",
] as const;

export type SolanaAuditCluster = (typeof SOLANA_AUDIT_CLUSTERS)[number];

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
