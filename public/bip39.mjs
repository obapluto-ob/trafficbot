export async function entropyToMnemonic(entropy, wordlist) {
  if (!(entropy instanceof Uint8Array) || entropy.length !== 16) {
    throw new TypeError("BIP-39 12-word phrases require exactly 128 bits of entropy.");
  }
  if (wordlist.length !== 2048) {
    throw new Error("The BIP-39 English wordlist is unavailable or invalid.");
  }
  if (!globalThis.crypto?.subtle) {
    throw new Error("Secure browser cryptography is unavailable. Open this page over HTTPS or localhost.");
  }

  const checksum = new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", entropy))[0]
    .toString(2).padStart(8, "0").slice(0, 4);
  const bits = Array.from(entropy, (byte) => byte.toString(2).padStart(8, "0")).join("") + checksum;
  const words = [];

  for (let offset = 0; offset < bits.length; offset += 11) {
    words.push(wordlist[Number.parseInt(bits.slice(offset, offset + 11), 2)]);
  }

  return words.join(" ");
}

export async function generateMnemonic(wordlist) {
  if (!globalThis.crypto?.getRandomValues) {
    throw new Error("A secure random number generator is unavailable in this browser.");
  }

  return entropyToMnemonic(globalThis.crypto.getRandomValues(new Uint8Array(16)), wordlist);
}

export function generateDemoKey() {
  if (!globalThis.crypto?.getRandomValues) {
    throw new Error("A secure random number generator is unavailable in this browser.");
  }

  const randomHex = Array.from(
    globalThis.crypto.getRandomValues(new Uint8Array(16)),
    (byte) => byte.toString(16).padStart(2, "0"),
  ).join("");
  return `DEMO-ONLY-NOT-A-PRIVATE-KEY-${randomHex}`;
}
