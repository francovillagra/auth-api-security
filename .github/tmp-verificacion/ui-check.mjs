// Recorrido en el navegador de la consola de la demo (verificación temporal; es el paso 4 de la «Prueba de aceptación» de demo/README.md).
// Usa el Google Chrome que ya trae el servidor de GitHub. Termina con código 1 si algo no da lo esperado.
import { chromium } from 'playwright-core';
import { appendFileSync } from 'node:fs';

const BASE = 'http://127.0.0.1:4200';
const lines = [];
let failed = 0;
const check = (ok, text) => {
  const line = `${ok ? 'OK   ' : 'FALLA'} ${text}`;
  lines.push(line);
  console.log(line);
  if (!ok) failed += 1;
};
const escape = (text) => text.replaceAll('%', '%25').replaceAll('\r', '%0D').replaceAll('\n', '%0A');

const browser = await chromium.launch({ channel: 'chrome' });
try {
  const problems = [];
  const watch = (page, label) => {
    page.on('console', (m) => { if (m.type() === 'error') problems.push(`${label} consola: ${m.text()}`); });
    page.on('pageerror', (e) => problems.push(`${label} excepción: ${e.message}`));
    page.on('requestfailed', (r) => problems.push(`${label} pedido fallido: ${r.url()}`));
  };

  // ---- Escritorio ----
  const desktop = await (await browser.newContext({ viewport: { width: 1280, height: 900 } })).newPage();
  watch(desktop, 'escritorio');
  await desktop.goto(BASE, { waitUntil: 'domcontentloaded' });
  await desktop.locator('#status[data-state="ok"]').waitFor({ timeout: 90_000 });
  check((await desktop.locator('#status').innerText()).includes('Sistema listo'), 'escritorio: arriba dice «Sistema listo»');

  await desktop.getByRole('button', { name: 'Crear la cuenta de práctica' }).click();
  await desktop.getByText('Cuenta creada').waitFor({ timeout: 30_000 });
  check(true, 'escritorio, parte 1: se creó la cuenta de práctica');

  for (const [selector, expected, verdict] of [['#attacks > li.card', 6, 'La API lo frenó'], ['#limits > li.card', 2, 'Límite conocido']]) {
    const cards = desktop.locator(selector);
    const count = await cards.count();
    check(count === expected, `escritorio: ${count} tarjetas en ${selector} (esperadas ${expected})`);
    for (let i = 0; i < count; i += 1) {
      const card = cards.nth(i);
      const title = (await card.locator('h3').innerText()).trim();
      try {
        await card.getByRole('button', { name: 'Probar este ataque' }).click({ timeout: 60_000 });
        await card.locator('.badge').waitFor({ timeout: 90_000 });
        const badge = (await card.locator('.badge').innerText()).trim();
        check(badge === verdict, `«${title}» terminó en «${badge}» (esperado «${verdict}»)`);
      } catch (error) {
        check(false, `«${title}» no llegó a un veredicto: ${String(error.message).split('\n')[0]}`);
      }
    }
  }
  const serverLog = (await desktop.locator('#serverlog').innerText()).trim();
  check(serverLog.length > 0 && !serverLog.includes('Todavía no hay movimiento'), 'escritorio: «Lo que registra la API» muestra movimiento real del servidor');
  await desktop.screenshot({ path: 'escritorio.png', fullPage: true });

  // ---- Celular ----
  const phone = await (await browser.newContext({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true })).newPage();
  watch(phone, 'celular');
  await phone.goto(BASE, { waitUntil: 'domcontentloaded' });
  await phone.locator('#status[data-state="ok"]').waitFor({ timeout: 90_000 });
  const overflow = await phone.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  check(overflow <= 1, `celular: sin desplazamiento horizontal (sobran ${overflow} px)`);
  await phone.screenshot({ path: 'celular.png', fullPage: true });

  check(problems.length === 0, `sin errores en la consola del navegador (${problems.length})${problems.length ? ': ' + problems.slice(0, 3).join(' | ') : ''}`);
} finally {
  await browser.close();
}

const ok = lines.length - failed;
const summary = `Recorrido en el navegador: ${ok} de ${lines.length} comprobaciones en orden`;
console.log(summary);
if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `### Recorrido en el navegador\n\n\`\`\`\n${lines.join('\n')}\n\`\`\`\n\n`);
if (failed) {
  console.log(`::error title=Recorrido en el navegador::${escape([summary, '', ...lines.filter((l) => l.startsWith('FALLA'))].join('\n'))}`);
  process.exit(1);
}
console.log(`::notice title=Recorrido en el navegador::${escape([summary, '', ...lines].join('\n'))}`);
