// Source of facet-crypto.js. Rebuild, with age-encryption@0.3.1 installed:
//   esbuild web/vendor/entry.js --bundle --format=esm --minify --outfile=web/vendor/facet-crypto.js
export { Decrypter, identityToRecipient } from "age-encryption";
export { ed25519 } from "@noble/curves/ed25519.js";
