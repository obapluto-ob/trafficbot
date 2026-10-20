"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { entropyToMnemonic, generateDemoKey, generateMnemonic } = require("../public/bip39.mjs");

test("BIP-39 zero-entropy vector produces the standard 12-word mnemonic", async () => {
  const { wordlist } = await import("@scure/bip39/wordlists/english.js");
  const phrase = await entropyToMnemonic(new Uint8Array(16), wordlist);

  assert.equal(phrase, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
});

test("secure generator returns distinct, valid 12-word BIP-39 phrases", async () => {
  const [{ wordlist }, { validateMnemonic }] = await Promise.all([
    import("@scure/bip39/wordlists/english.js"),
    import("@scure/bip39"),
  ]);
  const phrases = await Promise.all([generateMnemonic(wordlist), generateMnemonic(wordlist)]);

  for (const phrase of phrases) {
    assert.equal(phrase.split(" ").length, 12);
    assert.equal(validateMnemonic(phrase, wordlist), true);
  }
  assert.notEqual(phrases[0], phrases[1]);
});

test("BIP-39 12-word conversion rejects entropy with the wrong size", async () => {
  const { wordlist } = await import("@scure/bip39/wordlists/english.js");

  await assert.rejects(entropyToMnemonic(new Uint8Array(15), wordlist), /exactly 128 bits/);
});

test("demo key generator returns random strings that are explicitly not private keys", () => {
  const first = generateDemoKey();
  const second = generateDemoKey();

  assert.match(first, /^DEMO-ONLY-NOT-A-PRIVATE-KEY-[0-9a-f]{32}$/);
  assert.notEqual(first, second);
});
