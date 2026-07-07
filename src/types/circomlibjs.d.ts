declare module "circomlibjs" {
  export function buildPoseidon(): Promise<{
    (inputs: readonly bigint[]): unknown;
    F: {
      toString(value: unknown): string;
    };
  }>;
}
