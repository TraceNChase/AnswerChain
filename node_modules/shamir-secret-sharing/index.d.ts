/**
 * Splits a `secret` into `shares` number of shares, requiring `threshold` of them to reconstruct `secret`.
 *
 * @param secret The secret value to split into shares.
 * @param shares The total number of shares to split `secret` into. Must be at least 2 and at most 255.
 * @param threshold The minimum number of shares required to reconstruct `secret`. Must be at least 2 and at most 255.
 * @returns A list of `shares` shares.
 */
export declare function split(secret: Uint8Array, shares: number, threshold: number): Promise<Uint8Array[]>;
/**
 * Combines `shares` to reconstruct the secret.
 *
 * @param shares A list of shares to reconstruct the secret from. Must be at least 2 and at most 255.
 * @returns The reconstructed secret.
 */
export declare function combine(shares: Uint8Array[]): Promise<Uint8Array>;
