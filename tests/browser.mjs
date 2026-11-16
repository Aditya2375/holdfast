import { chromium } from "@playwright/test";
import { createServer } from "node:http";
import { readFile, mkdir } from "node:fs/promises";
import { resolve, extname } from "node:path";
import assert from "node:assert/strict";
import { allowed, stages, examples, launchPlan } from "../docs/model.js";
const root = resolve("docs");
const server = createServer(async (req, res) => {
  try {
    const path = resolve(
      root,
      "." +
        decodeURIComponent(
          new URL(req.url, "http://localhost").pathname.replace(
            /\/$/,
            "/index.html",
          ),
        ),
    );
    if (!path.startsWith(root + "/")) throw Error("path");
    res.setHeader(
      "Content-Type",
      {
        ".html": "text/html",
        ".js": "text/javascript",
        ".css": "text/css",
        ".svg": "image/svg+xml",
      }[extname(path)] || "application/octet-stream",
    );
    res.end(await readFile(path));
  } catch {
    res.writeHead(404);
    res.end("not found");
  }
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const base =
  process.env.HOLDFAST_URL || `http://127.0.0.1:${server.address().port}/`;
const shots = resolve(process.env.HOLDFAST_SHOTS || "build/screenshots");
await mkdir(shots, { recursive: true });
const browser = await chromium.launch({ headless: true });
let checks = 0;
const errors = [],
  requests = [],
  failed = [];
function ok(v, m) {
  assert.ok(v, m);
  checks++;
}
try {
  for (const width of [1440, 1024, 768, 390, 320]) {
    const page = await browser.newPage({
      viewport: { width, height: 1080 },
      deviceScaleFactor: 1,
    });
    page.on("pageerror", (e) => errors.push(e.message));
    page.on("console", (m) => {
      if (m.type() === "error") errors.push(m.text());
    });
    page.on("request", (r) => requests.push(r.url()));
    page.on("requestfailed", (r) => failed.push(r.url()));
    await page.goto(base);
    await page.waitForFunction(() =>
      document
        .querySelector("#command")
        .textContent.includes("./build/holdfast"),
    );
    ok(
      (await page.locator("#call-count").innerText()).startsWith(
        String(allowed.length),
      ),
      "allowlist count",
    );
    ok(
      await page.locator("body").evaluate((el) => el.scrollWidth <= innerWidth),
      `no page overflow ${width}`,
    );
    for (const [id, ex] of Object.entries(examples)) {
      await page.locator(`[data-example="${id}"]`).click();
      ok(
        (await page.locator("#expected").innerText()) === ex.expected,
        "preset behavior",
      );
      ok(
        (await page.locator("#command").innerText()) ===
          launchPlan({
            root: "/tmp/holdfast-root",
            program: "/bin/payload",
            args: ex.args,
            timeout: "5",
          }).command,
        "preset command",
      );
      ok(
        (await page
          .locator(`[data-example="${id}"]`)
          .getAttribute("aria-pressed")) === "true",
        "pressed state",
      );
    }
    for (const [i, s] of stages.entries()) {
      await page.locator("#stages button").nth(i).click();
      ok(
        (await page.locator("#stage-name").innerText()) === s.name,
        "stage title",
      );
      ok(
        (await page.locator("#stage-detail").innerText()) === s.detail,
        "stage detail",
      );
    }
    for (const name of allowed) {
      await page.locator("#syscall").fill(name);
      ok(
        (await page.locator("#verdict").innerText()) === "ALLOWLISTED",
        "allow " + name,
      );
    }
    for (const name of [
      "clone",
      "socket",
      "mount",
      "ptrace",
      "invalid_syscall",
    ]) {
      await page.locator("#syscall").fill(name);
      ok(
        (await page.locator("#verdict").innerText()) === "DEFAULT DENY",
        "deny " + name,
      );
    }
    await page.locator("#syscall").fill("<img src=x onerror=alert(1)>");
    ok(
      (await page.locator("#verdict").innerText()) === "NAME REQUIRED",
      "syscall injection rejected",
    );
    ok((await page.locator("img").count()) === 1, "no injected image");
    await page.locator("#root").fill("/");
    ok(await page.locator("#copy").isDisabled(), "invalid plan not copyable");
    ok(
      (await page.locator("#plan-error").innerText()).includes("absolute root"),
      "error visible",
    );
    const bad = "/tmp/<img src=x onerror=alert(1)>'$(echo nope)";
    await page.locator("#root").fill(bad);
    await page.locator("#args").fill("hello world\n'; echo nope; '\n");
    ok(
      (await page.locator("#command").innerText()) ===
        launchPlan({
          root: bad,
          program: "/bin/payload",
          args: "hello world\n'; echo nope; '\n",
          timeout: "5",
        }).command,
      "literal command text",
    );
    ok((await page.locator("img").count()) === 1, "no HTML interpolation");
    await page.locator('[data-example="inspect"]').click();
    await page.locator("#stages button").nth(0).click();
    await page.evaluate(() => {
      document.activeElement.blur();
      window.scrollTo({ top: 0, left: 0, behavior: "instant" });
    });
    const contrastFailures = await page.evaluate(() => {
      const rgb = (s) => (s.match(/[\d.]+/g) || []).map(Number);
      const lum = (c) =>
        c
          .slice(0, 3)
          .map((v) => v / 255)
          .map((v) => (v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4))
          .reduce((a, v, i) => a + v * [0.2126, 0.7152, 0.0722][i], 0);
      const failures = [];
      for (const el of document.querySelectorAll("body *")) {
        if (
          ![...el.childNodes].some(
            (n) => n.nodeType === 3 && n.textContent.trim(),
          ) ||
          el.getClientRects().length === 0
        )
          continue;
        const style = getComputedStyle(el);
        if (style.visibility === "hidden") continue;
        let parent = el,
          bg;
        while (parent) {
          bg = rgb(getComputedStyle(parent).backgroundColor);
          if (bg.length === 3 || bg[3] > 0) break;
          parent = parent.parentElement;
        }
        if (!parent) bg = [255, 255, 255];
        const fg = rgb(style.color),
          a = lum(fg),
          b = lum(bg),
          ratio = (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
        const large =
          parseFloat(style.fontSize) >= 24 ||
          (parseFloat(style.fontSize) >= 18.66 &&
            Number(style.fontWeight) >= 700);
        if (ratio < (large ? 3 : 4.5))
          failures.push({
            tag: el.tagName,
            id: el.id,
            text: el.textContent.trim().slice(0, 45),
            ratio,
            color: style.color,
          });
      }
      return failures;
    });
    ok(
      contrastFailures.length === 0,
      "text contrast " + JSON.stringify(contrastFailures),
    );
    for (const element of await page.locator("button,summary").all()) {
      const box = await element.boundingBox();
      if (box) ok(box.height >= 44, "44px tap target");
    }
    ok(
      await page
        .locator("h1")
        .evaluate(
          (el) =>
            el.getBoundingClientRect().height /
              parseFloat(getComputedStyle(el).lineHeight) <=
            3.1,
        ),
      "headline max three lines",
    );
    await page.screenshot({
      path: resolve(shots, `hero-${width}.png`),
      fullPage: true,
    });
    await page.screenshot({
      path: resolve(shots, `top-${width}.png`),
      fullPage: false,
    });
    await page.locator("summary").click();
    ok(await page.locator("#allowlist").isVisible(), "expanded allowlist");
    for (const name of allowed)
      ok(
        (await page.locator("#allowlist").innerText()).includes(name),
        "complete allowlist " + name,
      );
    await page.keyboard.press("Tab");
    ok(
      await page.evaluate(() => document.activeElement.tagName === "A"),
      "keyboard focus after details",
    );
    await page.close();
  }
  ok(errors.length === 0, "zero console/page errors " + errors.join(";"));
  ok(failed.length === 0, "zero failed requests " + failed.join(";"));
  ok(
    requests.every((u) => new URL(u).origin === new URL(base).origin),
    "no third-party requests",
  );
  console.log(
    JSON.stringify({
      status: "PASS",
      checks,
      widths: [1440, 1024, 768, 390, 320],
      errors,
      failed,
      requests: [...new Set(requests)],
    }),
  );
} finally {
  await browser.close();
  await new Promise((r) => server.close(r));
}
