import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import {
  allowed,
  stages,
  examples,
  launchPlan,
  syscallDecision,
  shellQuote,
} from "../docs/model.js";
let count = 0;
function ok(v, m) {
  assert.ok(v, m);
  count++;
}
function eq(a, b, m) {
  assert.deepEqual(a, b, m);
  count++;
}
const source = readFileSync("src/policy.h", "utf8");
eq(
  [...source.matchAll(/X\((\w+)\)/g)].map((m) => m[1]).sort(),
  allowed,
  "export exact",
);
eq(stages.length, 7, "all seven stages");
for (const name of allowed) {
  eq(syscallDecision(name).state, "allow", name);
  eq(syscallDecision("__NR_" + name).state, "allow", name + " alias");
}
for (const name of [
  "clone",
  "clone3",
  "fork",
  "vfork",
  "socket",
  "mount",
  "bpf",
  "ioctl",
  "ptrace",
  "keyctl",
  "setns",
  "unshare",
  "kill",
  "prctl",
])
  eq(syscallDecision(name).state, "deny", name);
for (const name of [
  "",
  "<img onerror=alert(1)>",
  "0x40000000",
  "A",
  "x\0",
  "x".repeat(49),
])
  eq(syscallDecision(name).state, "invalid", "invalid syscall");
for (const ex of Object.values(examples)) {
  const p = launchPlan({
    root: "/tmp/root",
    program: "/bin/payload",
    args: ex.args,
    timeout: "5",
  });
  ok(p.command.includes("'/bin/payload'"), "absoluteprogram");
  eq(p.argc, 2);
}
const valid = {
  root: "/tmp/root",
  program: "/bin/payload",
  args: "inspect",
  timeout: "5",
};
for (const patch of [
  { root: "" },
  { root: "/" },
  { root: "relative" },
  { root: "/tmp/root/" },
  { root: "/tmp\nroot" },
  { program: "relative" },
  { program: "/x\n" },
  { program: "/" + "x".repeat(4096) },
  { timeout: "0" },
  { timeout: "31" },
  { timeout: "-1" },
  { timeout: "1.5" },
  { args: "\0" },
  { args: "x".repeat(8193) },
]) {
  assert.throws(() => launchPlan({ ...valid, ...patch }));
  count++;
}
for (let t = 1; t <= 30; t++)
  eq(launchPlan({ ...valid, timeout: String(t) }).timeout, t);
eq(launchPlan({ ...valid, args: "" }).argc, 1);
eq(
  launchPlan({ ...valid, args: "x\n\ny\n" }).argc,
  5,
  "preserve explicit empty arguments",
);
// Shell parsing is checked independently against Python argv, without executing a runtime command.
const tricky = [
  "'",
  "$(touch /tmp/holdfast-should-never-exist)",
  "`id`",
  "; echo bad",
  "spaces and tabs\there",
  '"quoted"',
  "雪",
  "",
  "a\\b",
];
let seed = 8391;
const alphabet = "abc'\"$();|&` \\雪";
for (let i = 0; i < 500; i++) {
  let s = "";
  for (let j = 0; j < i % 70; j++) {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    s += alphabet[seed % alphabet.length];
  }
  const values = [...tricky, s];
  const command =
    "python3 -c " +
    shellQuote("import sys,json; print(json.dumps(sys.argv[1:]))") +
    " " +
    values.map(shellQuote).join(" ");
  const p = spawnSync("/bin/sh", ["-c", command], { encoding: "utf8" });
  eq(p.status, 0, "quote parser status");
  eq(JSON.parse(p.stdout), values, "literal argv");
}
console.log(JSON.stringify({ status: "PASS", assertions: count }));
