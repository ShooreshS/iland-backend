import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repoRoot = resolve(import.meta.dir, "..", "..");
const solanaRoot = resolve(repoRoot, "solana");

const readSolanaFile = (...parts: string[]): string =>
  readFileSync(resolve(solanaRoot, ...parts), "utf8");

describe("Phase 5 Solana audit program scaffold", () => {
  it("defines the CivicOS audit program workspace and program id", () => {
    const anchorToml = readSolanaFile("Anchor.toml");
    const cargoToml = readSolanaFile("Cargo.toml");
    const programCargoToml = readSolanaFile(
      "programs",
      "civicos-audit",
      "Cargo.toml",
    );

    expect(anchorToml).toContain("[programs.localnet]");
    expect(anchorToml).toContain(
      'civicos_audit = "2hnBkFjtErxbLCtTevhiW2GGTjDp1EHctshX3ebPEfRt"',
    );
    expect(cargoToml).toContain('"programs/civicos-audit"');
    expect(programCargoToml).toContain('anchor-lang = "0.32.1"');
  });

  it("implements the planned audit accounts and instructions", () => {
    const source = readSolanaFile(
      "programs",
      "civicos-audit",
      "src",
      "lib.rs",
    );

    [
      "initialize_registry",
      "create_poll",
      "commit_roots",
      "finalize_poll",
      "pub struct PollRegistry",
      "pub struct PollAccount",
      "pub struct PollRootAccount",
      "pub struct FinalResultAccount",
      "pub token_program: Option<Pubkey>",
      "pub enum PollStatus",
    ].forEach((expected) => {
      expect(source).toContain(expected);
    });
  });

  it("enforces root-chain and final-root invariants in the program source", () => {
    const source = readSolanaFile(
      "programs",
      "civicos-audit",
      "src",
      "lib.rs",
    );

    expect(source).toContain("previous_nullifier_root == poll.latest_nullifier_root");
    expect(source).toContain(
      "previous_vote_commitment_root == poll.latest_vote_commitment_root",
    );
    expect(source).toContain("batch_index == poll.next_batch_index");
    expect(source).toContain("accepted_count_delta > 0");
    expect(source).toContain("now >= poll.opens_at");
    expect(source).not.toContain("now < poll.closes_at");
    expect(source).toContain("token_mint.is_some() == token_program.is_some()");
    expect(source).toContain(
      "final_vote_commitment_root == poll.latest_vote_commitment_root",
    );
    expect(source).toContain(
      "final_nullifier_root == poll.latest_nullifier_root",
    );
  });

  it("keeps v1 limited to root anchoring instead of on-chain ZK verification", () => {
    const source = readSolanaFile(
      "programs",
      "civicos-audit",
      "src",
      "lib.rs",
    );

    [
      "verify_zk_proof",
      "verify_proof",
      "groth16",
      "ultraplonk",
      "honk",
      "alt_bn128",
    ].forEach((unsupportedV1Surface) => {
      expect(source.toLowerCase()).not.toContain(unsupportedV1Surface);
    });
    expect(source).toContain("commit_roots");
    expect(source).toContain("finalize_poll");
  });
});
