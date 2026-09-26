"""Exercise the real workbench in Chrome against an isolated demo deployment."""
import asyncio
import os
from pathlib import Path
import uuid
from playwright.async_api import async_playwright, expect

BASE = os.environ.get("KIBANA_RS_DEMO_URL", "http://100.115.129.28:8787")
CHROME = os.environ.get("CHROME_BIN", "/home/szymon/.nix-profile/bin/google-chrome")
ARTIFACTS = Path(os.environ.get("KIBANA_RS_SCREENSHOTS", "/tmp/kibana-rs-screenshots"))


async def main():
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    suffix = uuid.uuid4().hex[:8]
    rule_name = "Browser verification " + suffix
    case_name = "Browser investigation " + suffix
    policy_name = "Browser endpoints " + suffix
    assignment_name = "Browser telemetry " + suffix
    errors = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(executable_path=CHROME, headless=True)
        page = await browser.new_page(viewport={"width": 1440, "height": 1000})
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.on("dialog", lambda dialog: dialog.accept())
        await page.goto(BASE, wait_until="networkidle")
        await expect(page.locator("#connection")).to_contain_text("9.5.4 connected")
        await expect(page.locator("#page-error")).to_be_hidden()

        await page.locator("#create").click()
        await page.get_by_label("Rule name", exact=True).fill(rule_name)
        await page.get_by_label("Description", exact=True).fill("Disposable browser verification rule.")
        await page.locator("#submit-form").click()
        await expect(page.locator("#form-dialog")).not_to_be_visible(timeout=30000)
        await page.get_by_role("button", name=rule_name, exact=True).click()
        await expect(page.locator("#drawer-title")).to_have_text(rule_name)
        await page.get_by_role("button", name="Enable rule", exact=True).click()
        await expect(page.get_by_role("button", name="Disable rule", exact=True)).to_be_visible(timeout=30000)
        await page.get_by_role("button", name="Disable rule", exact=True).click()
        await expect(page.get_by_role("button", name="Enable rule", exact=True)).to_be_visible(timeout=30000)
        await page.get_by_role("button", name="Edit rule", exact=True).click()
        rule_name += " updated"
        await page.get_by_label("Rule name", exact=True).fill(rule_name)
        await page.locator("#submit-form").click()
        await expect(page.locator("#form-dialog")).not_to_be_visible(timeout=30000)
        await page.get_by_role("button", name=rule_name, exact=True).click()
        await page.locator('#drawer [data-delete="rules"]').click()
        await expect(page.locator("#drawer")).to_be_hidden(timeout=30000)
        await expect(page.get_by_role("button", name=rule_name, exact=True)).to_have_count(0)
        print("PASS rule create, enable, disable, edit, delete")

        await page.locator('.nav-item[data-view="cases"]').click()
        await page.locator("#create").click()
        await page.get_by_label("Case title", exact=True).fill(case_name)
        await page.get_by_label("Description", exact=True).fill("Disposable browser verification case.")
        await page.locator("#submit-form").click()
        await expect(page.locator("#form-dialog")).not_to_be_visible(timeout=30000)
        await page.get_by_role("button", name=case_name, exact=True).click()
        await page.get_by_role("button", name="Start investigation", exact=True).click()
        await expect(page.locator("#drawer .badge.in-progress")).to_be_visible(timeout=30000)
        await page.locator("#comment-text").fill("Verified from a real browser against Kibana.")
        await page.locator("#add-comment").click()
        await expect(page.locator("#case-comments")).to_contain_text("Verified from a real browser", timeout=30000)
        await page.get_by_role("button", name="Close case", exact=True).click()
        await expect(page.locator("#drawer .badge.closed")).to_be_visible(timeout=30000)
        await page.locator('#drawer [data-delete="cases"]').click()
        await expect(page.locator("#drawer")).to_be_hidden(timeout=30000)
        print("PASS case create, investigate, comment, close, delete")

        await page.locator('.nav-item[data-view="policies"]').click()
        await page.locator("#create").click()
        await page.get_by_label("Policy name", exact=True).fill(policy_name)
        await page.get_by_label("Description", exact=True).fill("Disposable browser verification policy.")
        await page.locator("#submit-form").click()
        await expect(page.locator("#form-dialog")).not_to_be_visible(timeout=30000)
        await page.get_by_role("button", name=policy_name, exact=True).click()
        await page.get_by_role("button", name="Assign integration", exact=True).click()
        await page.get_by_label("Integration policy name", exact=True).fill(assignment_name)
        select = page.get_by_label("Installed package", exact=True)
        assert await select.locator('option[value^="security_detection_engine|"]').count() == 0
        system = await select.locator("option").evaluate_all("opts => opts.find(o => o.value.startsWith('system|')).value")
        await select.select_option(system)
        await page.locator("#submit-form").click()
        await expect(page.locator("#form-dialog")).not_to_be_visible(timeout=60000)
        await page.locator('.nav-item[data-view="integrations"]').click()
        await page.locator('[data-tab="assigned"]').click()
        await page.get_by_role("button", name=assignment_name, exact=True).click()
        await page.get_by_role("button", name="Remove assignment", exact=True).click()
        await expect(page.locator("#drawer")).to_be_hidden(timeout=30000)
        await page.locator('.nav-item[data-view="policies"]').click()
        await page.get_by_role("button", name=policy_name, exact=True).click()
        await page.locator('#drawer [data-delete="policies"]').click()
        await expect(page.locator("#drawer")).to_be_hidden(timeout=30000)
        print("PASS agent policy create, integration assignment, assignment removal, policy delete")

        await page.locator('.nav-item[data-view="rules"]').click()
        await page.get_by_role("button", name="Failed privileged authentication", exact=True).wait_for()
        await expect(page.locator("#toast")).to_be_hidden(timeout=10000)
        await page.screenshot(path=str(ARTIFACTS / "rules-desktop.png"), full_page=True)
        await page.locator('.nav-item[data-view="policies"]').click()
        await page.get_by_role("button", name="SOC Linux endpoints", exact=True).wait_for()
        await expect(page.get_by_role("row").filter(has=page.get_by_role("button", name="SOC Linux endpoints", exact=True))).to_contain_text("1 assigned")
        await page.screenshot(path=str(ARTIFACTS / "fleet-desktop.png"), full_page=True)
        await page.locator('.nav-item[data-view="integrations"]').click()
        await expect(page.locator(".integration-card").first).to_be_visible(timeout=30000)
        await expect(page.locator(".integration-card").filter(has_text="Prebuilt Security Detection Rules")).to_contain_text("Assets only")
        await page.screenshot(path=str(ARTIFACTS / "integrations-desktop.png"), full_page=True)
        await page.locator('.nav-item[data-view="agents"]').click()
        await expect(page.get_by_role("heading", name="No agents enrolled")).to_be_visible()
        await page.locator('.nav-item[data-view="activity"]').click()
        await expect(page.locator(".activity-list")).to_contain_text("Created detection rule")
        print("PASS empty agent state and real operation history")

        await page.set_viewport_size({"width": 390, "height": 844})
        await page.locator('.nav-item[data-view="rules"]').click()
        await page.get_by_role("button", name="Failed privileged authentication", exact=True).wait_for()
        assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth"), "Page overflows phone viewport"
        await page.screenshot(path=str(ARTIFACTS / "rules-mobile.png"), full_page=True)
        await page.get_by_role("button", name="Failed privileged authentication", exact=True).click()
        await expect(page.locator("#drawer-title")).to_have_text("Failed privileged authentication")
        await page.screenshot(path=str(ARTIFACTS / "rule-detail-mobile.png"), full_page=True)
        print("PASS phone viewport and rule inspection")
        assert not errors, errors
        print("PASS no uncaught browser errors")
        print("Screenshots:", ARTIFACTS)
        await browser.close()


asyncio.run(main())
