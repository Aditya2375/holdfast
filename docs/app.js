import {
  allowed,
  stages,
  examples,
  launchPlan,
  syscallDecision,
} from "./model.js";
const $ = (id) => document.getElementById(id);
function update() {
  try {
    const p = launchPlan({
      root: $("root").value,
      program: $("program").value,
      args: $("args").value,
      timeout: $("timeout").value,
    });
    $("command").textContent = p.command;
    $("argc").textContent = p.argc + " ARGV ENTRIES";
    $("wall").textContent = p.timeout + "s WALL";
    $("plan-error").textContent = "";
    $("copy").disabled = false;
  } catch (e) {
    $("plan-error").textContent = e.message;
    $("command").textContent = "Plan unavailable. Fix the fields on the left.";
    $("argc").textContent = "INVALID INPUT";
    $("wall").textContent = "";
    $("copy").disabled = true;
  }
}
function gate() {
  const d = syscallDecision($("syscall").value);
  $("decision").dataset.state = d.state;
  $("verdict").textContent =
    d.state === "allow"
      ? "ALLOWLISTED"
      : d.state === "deny"
        ? "DEFAULT DENY"
        : "NAME REQUIRED";
  $("decision-title").textContent = d.title;
  $("decision-detail").textContent = d.detail;
}
function stage(index) {
  const s = stages[index];
  $("stage-number").textContent =
    "STAGE " + String(index + 1).padStart(2, "0") + " / 07";
  $("stage-name").textContent = s.name;
  $("stage-api").textContent = s.api;
  $("stage-detail").textContent = s.detail;
  for (const [i, b] of [...$("stages").children].entries())
    b.setAttribute("aria-pressed", String(i === index));
}
for (const [i, s] of stages.entries()) {
  const b = document.createElement("button");
  b.type = "button";
  const n = document.createElement("span");
  n.textContent = String(i + 1).padStart(2, "0");
  b.append(n, document.createTextNode(s.name));
  b.addEventListener("click", () => stage(i));
  $("stages").append(b);
}
for (const b of document.querySelectorAll("[data-example]"))
  b.addEventListener("click", () => {
    const ex = examples[b.dataset.example];
    $("root").value = "/tmp/holdfast-root";
    $("program").value = "/bin/payload";
    $("args").value = ex.args;
    $("timeout").value = "5";
    $("expected").textContent = ex.expected;
    $("syscall").value = ex.syscall;
    for (const other of document.querySelectorAll("[data-example]"))
      other.setAttribute("aria-pressed", String(other === b));
    gate();
    update();
  });
for (const b of document.querySelectorAll("[data-call]"))
  b.addEventListener("click", () => {
    $("syscall").value = b.dataset.call;
    gate();
  });
$("plan-form").addEventListener("submit", (e) => {
  e.preventDefault();
  update();
});
for (const id of ["root", "program", "args", "timeout"])
  $(id).addEventListener("input", () => {
    for (const b of document.querySelectorAll("[data-example]"))
      b.setAttribute("aria-pressed", "false");
    $("expected").textContent =
      "Custom plan. Expected results depend on your own native program. No command has run in this page.";
    update();
  });
$("syscall").addEventListener("input", gate);
$("copy").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText($("command").textContent);
    $("copy").textContent = "Copied";
  } catch {
    $("copy").textContent = "Select command";
    $("command").focus();
  }
  setTimeout(() => {
    $("copy").textContent = "Copy";
  }, 1600);
});
$("call-count").textContent =
  allowed.length + " ALLOWLISTED / EVERYTHING ELSE DENIED";
$("allowlist").textContent = allowed.join(" · ");
$("expected").textContent = examples.inspect.expected;
stage(0);
gate();
update();
