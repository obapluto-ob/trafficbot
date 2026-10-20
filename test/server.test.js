"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { isPublicIPv4, normalizeTarget, inspectHtml, createPinnedLookup } = require("../server");

test("public IPv4 guard accepts public addresses and rejects private or reserved ranges", () => {
  assert.equal(isPublicIPv4("8.8.8.8"), true);
  for (const address of ["127.0.0.1", "10.0.0.2", "172.16.0.1", "192.168.1.1", "169.254.1.1", "224.0.0.1"]) {
    assert.equal(isPublicIPv4(address), false, address);
  }
});

test("target validation allows HTTP(S) and rejects unsupported or credentialed URLs", () => {
  assert.equal(normalizeTarget("https://example.com/path").hostname, "example.com");
  assert.equal(normalizeTarget("example.com/path").protocol, "https:");
  assert.throws(() => normalizeTarget("file:///etc/passwd"), /Only HTTP and HTTPS/);
  assert.throws(() => normalizeTarget("https://user:pass@example.com"), /usernames or passwords/);
  assert.throws(() => normalizeTarget("http://127.0.0.1"), /publicly routable/);
});

test("pinned DNS lookup supports both Node callback signatures", () => {
  const lookup = createPinnedLookup("203.0.113.8");
  lookup("example.com", {}, (error, address, family) => {
    assert.equal(error, null);
    assert.equal(address, "203.0.113.8");
    assert.equal(family, 4);
  });
  lookup("example.com", { all: true }, (error, addresses) => {
    assert.equal(error, null);
    assert.deepEqual(addresses, [{ address: "203.0.113.8", family: 4 }]);
  });
  lookup("example.com", (error, address, family) => {
    assert.equal(error, null);
    assert.equal(address, "203.0.113.8");
    assert.equal(family, 4);
  });
});

test("HTML checks identify missing metadata, headings, and image alt text", () => {
  const result = inspectHtml(
    '<html><head><title>Example</title></head><body><img src="/hero.png"><a href="/start">Get started</a></body></html>',
    {},
    "https://example.com",
  );
  assert.equal(result.title, "Example");
  assert.equal(result.h1Count, 0);
  assert.equal(result.imagesMissingAlt, 1);
  assert.equal(result.hasCta, true);
  assert.ok(result.checks.some(({ name }) => name === "Main heading"));
  assert.ok(result.checks.some(({ name }) => name === "Image alternatives"));
});

test("likely JavaScript app shells do not produce misleading empty-content findings", () => {
  const result = inspectHtml(
    '<html><head><title>Example</title></head><body><div id="root"></div><script src="/app.js"></script></body></html>',
    {},
    "https://example.com",
  );
  assert.equal(result.likelyClientRendered, true);
  assert.ok(result.checks.some(({ name }) => name === "JavaScript-rendered page"));
  assert.ok(!result.checks.some(({ name }) => ["Main heading", "Navigation links", "Call to action"].includes(name)));
});
