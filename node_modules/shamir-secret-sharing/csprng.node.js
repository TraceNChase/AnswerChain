"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getRandomBytes = void 0;
const node_crypto_1 = require("node:crypto");
function getRandomBytes(numBytes) {
    return new Uint8Array((0, node_crypto_1.randomBytes)(numBytes).buffer);
}
exports.getRandomBytes = getRandomBytes;
//# sourceMappingURL=csprng.node.js.map