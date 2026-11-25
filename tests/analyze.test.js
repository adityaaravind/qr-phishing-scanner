// Run: node tests/analyze.test.js
// Loads only the analysis engine from app.js (everything before the UI section).
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const assert = require("assert");

const src = fs.readFileSync(path.join(__dirname, "..", "assets", "js", "app.js"), "utf8");
const engine = src.slice(0, src.indexOf("/* ================= UI"));
const ctx = { URL }; // vm contexts have no URL global
vm.createContext(ctx);
vm.runInContext(engine + ";this.analyze = analyze;", ctx);
const analyze = ctx.analyze;

const titles = (raw) => analyze(raw).checks.map((c) => c.title);
const flagged = (raw, needle) => titles(raw).some((t) => t.indexOf(needle) >= 0);

let failed = 0;
function test(name, fn) {
  try { fn(); console.log("ok   " + name); }
  catch (e) { failed++; console.log("FAIL " + name + "\n     " + e.message); }
}

// True positives (must keep working)
test("lookalike paypa1 is flagged", () => {
  assert.ok(flagged("https://paypa1.example/account/verify", "PayPal"));
});
test("subdomain costume is flagged", () => {
  assert.ok(flagged("https://paypal.com.login-verify.example/signin", "Dressed up as PayPal"));
});
test("official domain is not flagged as brand", () => {
  const t = titles("https://www.paypal.com/signin");
  assert.ok(t.some((x) => x.indexOf("Domain really is PayPal") === 0));
  assert.ok(!t.some((x) => /Lookalike|Typosquat|Dressed up|embedded/.test(x)));
});
test("bare embedded brand still flagged", () => {
  assert.ok(flagged("https://secure-paypalsupport.example/", "embedded") || flagged("https://paypalsupport.example/", "Brand name embedded"));
});

// False positives found in review: short brand keys matched as substrings
test("'groups' subdomain is not UPS", () => {
  assert.ok(!flagged("https://groups.example.org/", "UPS"));
});
test("'olive' domain is not Microsoft (live)", () => {
  assert.ok(!flagged("https://olive.example.org/", "Microsoft"));
});
test("'delivery' subdomain is not Microsoft (live)", () => {
  assert.ok(!flagged("https://delivery.example.org/", "Microsoft"));
});

// Wi-Fi: escaped separators inside SSID/password
test("Wi-Fi escaped semicolon stays in the SSID", () => {
  const r = analyze("WIFI:T:WPA;S:Cafe\\;Guest;P:pa\\;ss\\:word;H:false;;");
  assert.strictEqual(r.kind, "wifi");
  assert.strictEqual(r.meta.ssid, "Cafe;Guest");
  assert.ok(!r.checks.some((c) => c.title.indexOf("Open network") === 0));
});
test("Wi-Fi escaped backslash and colon parse", () => {
  const r = analyze("WIFI:S:a\\\\b:c;T:WEP;;");
  assert.strictEqual(r.meta.ssid, "a\\b:c");
  assert.ok(r.checks.some((c) => c.title === "WEP security"));
});
test("Wi-Fi open network still flagged", () => {
  assert.ok(analyze("WIFI:S:Free;T:nopass;;").checks.some((c) => c.title.indexOf("Open network") === 0));
});

// host:port is not a scheme
test("localhost:8080 is a web link, not an app scheme", () => {
  const r = analyze("localhost:8080");
  assert.strictEqual(r.kind, "url");
  assert.strictEqual(r.host, "localhost");
  assert.ok(!r.checks.some((c) => c.title.indexOf("Opens an app") === 0));
});
test("IP:port with path is a web link", () => {
  const r = analyze("192.168.1.5:8443/login");
  assert.strictEqual(r.kind, "url");
  assert.ok(r.checks.some((c) => c.title.indexOf("Raw IP") === 0));
});
test("real custom scheme still treated as app link", () => {
  assert.ok(flagged("myapp://open?x=1", "Opens an app"));
});

if (failed) { console.log("\n" + failed + " test(s) failed"); process.exit(1); }
console.log("\nall tests passed");
