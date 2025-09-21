"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getRandomBytes = void 0;
function getRandomBytes(numBytes) {
    return crypto.getRandomValues(new Uint8Array(numBytes));
}
exports.getRandomBytes = getRandomBytes;
//# sourceMappingURL=csprng.js.map