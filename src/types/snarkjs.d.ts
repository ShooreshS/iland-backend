declare module "snarkjs" {
  export const groth16: {
    verify(
      verificationKey: unknown,
      publicSignals: readonly string[],
      proof: unknown,
    ): Promise<boolean>;
  };

  export const curves: {
    terminate(): Promise<void>;
  };
}
