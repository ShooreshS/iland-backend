import { buildPoseidon } from "circomlibjs";

const BN254_SCALAR_FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const HEX_64_PATTERN = /^[0-9a-f]{64}$/;
const DECIMAL_PATTERN = /^(0|[1-9][0-9]*)$/;

let poseidonPromise: ReturnType<typeof buildPoseidon> | null = null;

const getPoseidon = (): ReturnType<typeof buildPoseidon> => {
  poseidonPromise ??= buildPoseidon();
  return poseidonPromise;
};

export const normalizeBn254FieldElement = (
  value: string | number | bigint,
): bigint => {
  if (typeof value === "bigint") {
    return value % BN254_SCALAR_FIELD;
  }

  if (typeof value === "number") {
    if (!Number.isInteger(value) || value < 0) {
      throw new TypeError("Expected a non-negative integer field element.");
    }
    return BigInt(value) % BN254_SCALAR_FIELD;
  }

  const normalized = value.trim().toLowerCase();
  if (HEX_64_PATTERN.test(normalized)) {
    return BigInt(`0x${normalized}`) % BN254_SCALAR_FIELD;
  }

  if (DECIMAL_PATTERN.test(normalized)) {
    return BigInt(normalized) % BN254_SCALAR_FIELD;
  }

  throw new TypeError("Expected a 32-byte hex or decimal field element.");
};

export const fieldElementToHex64 = (value: string | number | bigint): string =>
  normalizeBn254FieldElement(value).toString(16).padStart(64, "0");

export const poseidonHashFields = async (
  inputs: readonly (string | number | bigint)[],
): Promise<string> => {
  const poseidon = await getPoseidon();
  return poseidon.F.toString(
    poseidon(inputs.map((input) => normalizeBn254FieldElement(input))),
  );
};

export const poseidonHashHex64 = async (
  inputs: readonly (string | number | bigint)[],
): Promise<string> => fieldElementToHex64(await poseidonHashFields(inputs));

