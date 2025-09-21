import { randomBytes } from 'node:crypto';
export function getRandomBytes(numBytes) {
    return new Uint8Array(randomBytes(numBytes).buffer);
}
//# sourceMappingURL=csprng.node.js.map