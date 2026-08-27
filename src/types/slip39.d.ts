/**
 * Minimal type surface for the `slip39` reference implementation
 * (https://github.com/ilap/slip39-js) as used by mnemonicKeyring.service.
 */
declare module "slip39" {
  interface Slip39Node {
    mnemonics: string[];
  }

  interface Slip39Options {
    passphrase?: string;
    threshold?: number;
    /** [memberThreshold, memberCount, description?] per group. */
    groups?: Array<[number, number, string?]>;
    iterationExponent?: number;
  }

  class Slip39 {
    static fromArray(masterSecret: number[], options?: Slip39Options): Slip39;
    static recoverSecret(mnemonics: string[], passphrase?: string): number[];
    fromPath(path: string): Slip39Node;
  }

  export default Slip39;
}
