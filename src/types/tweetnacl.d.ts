// Local type stub for tweetnacl (no @types/tweetnacl package exists)
declare module "tweetnacl" {
  export interface SignKeyPair {
    publicKey: Uint8Array;
    secretKey: Uint8Array;
  }

  export namespace sign {
    function keyPair(): SignKeyPair;
    namespace keyPair {
      function fromSecretKey(secretKey: Uint8Array): SignKeyPair;
    }
    function detached(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
    namespace detached {
      function verify(
        message: Uint8Array,
        signature: Uint8Array,
        publicKey: Uint8Array
      ): boolean;
    }
  }

  // Default export (backward compatibility)
  const nacl: {
    sign: typeof sign;
  };
  export default nacl;
}
