import { test, expect, gotoView } from "../fixtures/app";
import { mockBackend } from "../fixtures/backend";
import { installWallet } from "../fixtures/wallet";

/**
 * M-16: the SPA ships a Content-Security-Policy, and the app still works under it.
 *
 * A CSP is only worth having if nothing routine violates it — a policy that
 * breaks the page gets removed by the next person on call. The headers live in
 * `docker/nginx.conf.template`, so proving them takes the real image: the dev
 * server sends no headers at all, and a test against it would pass no matter
 * what the policy said.
 *
 * Point CSP_ORIGIN at a running frontend container to run this:
 *
 * ```text
 * docker build -f docker/Dockerfile.frontend -t bridge-frontend .
 * docker run -d --name csp -p 127.0.0.1:18099:8080 bridge-frontend
 * CSP_ORIGIN=http://127.0.0.1:18099 bunx playwright test e2e/app/csp.spec.ts
 * ```
 *
 * Skipped (not failed) without it: the suite must stay runnable with no Docker.
 */

const ORIGIN = process.env.CSP_ORIGIN;

test.describe("Content-Security-Policy", () => {
  test.skip(!ORIGIN, "set CSP_ORIGIN to a served frontend container");

  test("the served page carries the policy", async ({ page }) => {
    const res = await page.goto(ORIGIN!);
    const csp = res?.headers()["content-security-policy"] ?? "";
    // The directives that stop an injected script from re-targeting a transfer.
    expect(csp).toContain("script-src 'self'");
    expect(csp).not.toContain("script-src 'self' 'unsafe-inline'");
    expect(csp).not.toContain("unsafe-eval");
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("base-uri 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(res?.headers()["x-content-type-options"]).toBe("nosniff");
    expect(res?.headers()["x-frame-options"]).toBe("DENY");
  });

  test("the app boots and renders under the policy, with no violations", async ({ page }) => {
    const violations: string[] = [];
    await page.addInitScript(() => {
      document.addEventListener("securitypolicyviolation", (e) => {
        (window as unknown as { __csp: string[] }).__csp ??= [];
        (window as unknown as { __csp: string[] }).__csp.push(
          `${e.violatedDirective} blocked ${e.blockedURI}`
        );
      });
    });
    page.on("console", (m) => {
      if (m.type() === "error" && /Content Security Policy/i.test(m.text())) violations.push(m.text());
    });

    await mockBackend(page, {});
    await installWallet(page, {});
    await page.goto(ORIGIN!);

    // The bundle executed and React mounted — i.e. `script-src 'self'` did not
    // block the one module the build emits.
    await expect(page.locator("#root")).not.toBeEmpty();
    await expect(page.getByRole("button", { name: "Bridge", exact: true })).toBeVisible();
    await gotoView(page, "Bridge");
    await expect(page.getByRole("heading", { name: "Bridge" })).toBeVisible();

    const reported = await page.evaluate(() => (window as unknown as { __csp?: string[] }).__csp ?? []);
    expect(reported, `CSP violations: ${reported.join("; ")}`).toHaveLength(0);
    expect(violations, violations.join("; ")).toHaveLength(0);
  });

  /**
   * `style-src 'self'` alone would drop every `style={{…}}` attribute React
   * renders — silently, since a blocked attribute is not an error, just a lost
   * rule. `style-src-attr 'unsafe-inline'` is what keeps them, while injected
   * <style> blocks and remote stylesheets stay blocked.
   */
  test("inline style attributes still apply", async ({ page }) => {
    await mockBackend(page, {});
    await installWallet(page, {});
    await page.goto(ORIGIN!);
    const applied = await page.evaluate(() => {
      const d = document.createElement("div");
      d.setAttribute("style", "margin-bottom: 20px");
      document.body.appendChild(d);
      const v = getComputedStyle(d).marginBottom;
      d.remove();
      return v;
    });
    expect(applied).toBe("20px");
  });
});
