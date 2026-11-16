"use strict";

// Todo lo que viene del servidor se escribe con textContent: nada se interpreta como HTML.

const $ = (selector) => document.querySelector(selector);
const POLL_MS = 1500;
const LEVEL_LABEL = { info: "info", warn: "alerta", error: "error" };

const ui = {
  data: null,         // última respuesta de /api/state
  notes: {},          // mensajes por paso o ataque: {clave: {text, kind}}
  busy: false,        // hay una acción en curso: se bloquean los demás botones
  running: null,      // id del ataque en curso
  resetArmed: false,
  refreshing: false,
  again: false,
};

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (value !== false && value != null) node.setAttribute(key, value === true ? "" : String(value));
  }
  node.append(...children.filter((child) => child != null && child !== false));   // append() escribiría «null» para un hijo nulo
  return node;
}

async function call(method, url, body) {
  const options = { method, cache: "no-store", headers: {} };
  if (body !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  const response = await fetch(url, options);
  let data = null;
  try {
    data = await response.json();
  } catch {
    // respuesta sin cuerpo
  }
  return { ok: response.ok, status: response.status, data };
}

// ---- estado general ------------------------------------------------------------------------------------------------

function setStatus(kind, text) {
  const node = $("#status");
  node.dataset.state = kind;
  node.textContent = text;
}

function formatTime(iso) {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? "" : date.toLocaleTimeString("es-AR", { hour12: false });
}

function formatDate(iso) {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? "" : date.toLocaleDateString("es-AR");
}

async function refresh() {
  if (ui.refreshing) {   // ya hay una consulta en camino: pedir otra apenas termine, para no mostrar datos viejos
    ui.again = true;
    return;
  }
  ui.refreshing = true;
  try {
    do {
      ui.again = false;
      let data = null;
      try {
        const result = await call("GET", "/api/state");
        if (!result.ok) throw new Error(String(result.status));
        data = result.data;
      } catch {
        setStatus("error", "No se puede hablar con la consola");
      }
      if (data) {
        ui.data = data;
        setStatus(data.api_ready ? "ok" : "wait", data.api_ready ? "Sistema listo" : "Esperando que la API termine de arrancar…");
        render();
      }
    } while (ui.again);
  } finally {
    ui.refreshing = false;
  }
}

// ---- acciones --------------------------------------------------------------------------------------------------------

function setNote(key, text, kind = "warn") {
  ui.notes[key] = { text, kind };
}

async function act(step, method, url, body) {
  if (ui.busy) return null;
  ui.busy = true;
  delete ui.notes[step];
  render();
  let result = null;
  try {
    result = await call(method, url, body);
    if (!result.ok) setNote(step, (result.data && result.data.error) || `Error ${result.status}`);
  } catch {
    setNote(step, "No se puede hablar con la consola.");
  } finally {
    ui.busy = false;
    await refresh();
  }
  return result;
}

async function runAttack(id) {
  if (ui.busy) return;
  ui.running = id;
  await act(id, "POST", "/api/scenario", { id });
  ui.running = null;
  render();
}

function button(text, onClick, { primary = false, attack = false, disabled = false, id = null } = {}) {
  const node = el("button", { type: "button", class: primary ? "btn primary" : attack ? "btn attack" : "btn", text, id });
  node.disabled = disabled || ui.busy;
  node.addEventListener("click", onClick);
  return node;
}

function note(key) {
  const entry = ui.notes[key];
  return entry ? el("p", { class: "note", "data-kind": entry.kind, text: entry.text, role: "alert" }) : null;
}

function mono(text) {
  return el("span", { class: "mono", text });
}

function noteKey(key) {
  const entry = ui.notes[key];
  return entry ? `${entry.kind}:${entry.text}` : "";
}

// ---- parte 1: el recorrido del cliente -----------------------------------------------------------------------------------

function table(headers, rows) {
  if (!rows.length) return el("p", { class: "muted", text: "Nada para mostrar." });
  return el("div", { class: "table-wrap" }, el("table", {},
    el("thead", {}, el("tr", {}, ...headers.map((h) => el("th", { text: h })))),
    el("tbody", {}, ...rows.map((row) => el("tr", {}, ...row.map((cell) => el("td", { text: cell == null || cell === "" ? "-" : String(cell) }))))),
  ));
}

function buildSteps(d) {
  const customer = d.customer;
  const has = Boolean(customer);
  const open = has && customer.session === "active";
  const profile = has ? customer.profile : null;
  const list = d.admin_list;
  const ready = d.api_ready;
  const stateOf = (done, unlocked) => (done ? "done" : unlocked ? "active" : "locked");

  return [
    {
      key: "create", title: "Crear la cuenta de un cliente", state: stateOf(has, true),
      sig: [has, has && customer.email, ui.busy, noteKey("create"), ready],
      build: () => has
        ? [el("p", { class: "summary" }, "Cuenta creada: ", mono(customer.email), ". Existe solo mientras la demo esté encendida.")]
        : [
            el("p", { text: `Un cliente nuevo se registra en la tienda. La API le crea la cuenta y le entrega dos «llaves»: una de acceso, que vale ${d.limits.access_minutes} minutos, y una de renovación, que vale ${d.limits.refresh_days} días y se puede usar una sola vez.` }),
            el("div", { class: "actions" }, button("Crear la cuenta de práctica", () => act("create", "POST", "/api/customer"), { primary: true, disabled: !ready })),
            note("create"),
          ],
    },
    {
      key: "profile", title: "Ver el perfil", state: stateOf(Boolean(profile), has),
      sig: [has, open, JSON.stringify(profile), ui.busy, noteKey("profile")],
      build: () => [
        el("p", { text: "Con la llave de acceso, el cliente pide sus datos. Sin llave, la API no contesta." }),
        profile
          ? el("dl", { class: "facts" },
              el("div", {}, el("dt", { text: "Correo" }), el("dd", {}, mono(profile.email))),
              el("div", {}, el("dt", { text: "Nombre" }), el("dd", { text: profile.name || "-" })),
              el("div", {}, el("dt", { text: "Rol" }), el("dd", { text: profile.role_label })),
              el("div", {}, el("dt", { text: "Alta" }), el("dd", { text: formatDate(profile.created_at) })))
          : null,
        el("div", { class: "actions" },
          button("Pedir mi perfil", () => act("profile", "POST", "/api/profile", {}), { primary: !profile, disabled: !open }),
          button("Probar sin llave", async () => {
            const result = await act("profile", "POST", "/api/profile", { anonymous: true });
            if (result && result.ok && result.data && result.data.refused) {
              setNote("profile", `Sin llave, la API rechazó el pedido (${result.data.status}). Nadie entra sin identificarse.`, "ok");
              render();
            }
          }, { disabled: !has })),
        note("profile"),
      ],
    },
    {
      key: "session", title: "Mantener o cerrar la sesión", state: stateOf(false, has),
      sig: [has, has && customer.session, has && customer.access_expires_at, ui.busy, noteKey("session")],
      build: () => [
        el("p", { text: "Para no pedir la contraseña a cada rato, el cliente renueva su sesión: la API cambia la llave de renovación por una nueva y la anterior deja de servir. También puede cerrar sesión y volver a entrar." }),
        has
          ? el("p", { class: "muted" }, open
              ? `Sesión abierta.${customer.access_expires_at ? ` La llave de acceso vence a las ${formatTime(customer.access_expires_at)}.` : ""}`
              : "Sesión cerrada.")
          : null,
        el("div", { class: "actions" },
          ...(open
            ? [
                button("Renovar la sesión", () => act("session", "POST", "/api/renew"), { primary: true }),
                button("Cerrar sesión", () => act("session", "POST", "/api/logout")),
              ]
            : [button("Entrar de nuevo", () => act("session", "POST", "/api/login"), { primary: has, disabled: !has })])),
        note("session"),
      ],
    },
    {
      key: "accounts", title: "La administración ve las cuentas", state: stateOf(Boolean(list), true),
      sig: [JSON.stringify(list), ui.busy, noteKey("accounts"), ready],
      build: () => [
        el("p", { text: "Solo una cuenta con rol de administración puede ver el listado de cuentas, y el listado nunca incluye las contraseñas." }),
        el("div", { class: "actions" }, button(list ? "Actualizar el listado" : "Ver las cuentas como administración", () => act("accounts", "POST", "/api/accounts"), { primary: !list, disabled: !ready })),
        note("accounts"),
        list
          ? el("div", {},
              table(["Correo", "Nombre", "Rol", "Alta"], list.users.map((u) => [u.email, u.name, u.role_label, formatDate(u.created_at)])),
              el("p", { class: "muted small", text: `Se muestran ${list.shown} de ${list.total}.` }))
          : null,
      ],
    },
  ];
}

function renderSteps(d) {
  const list = $("#steps");
  buildSteps(d).forEach((step, index) => {
    let item = list.children[index];
    if (!item) {
      item = el("li", { class: "step" });
      list.append(item);
    }
    const signature = JSON.stringify(step.sig);
    if (item.dataset.sig !== signature) {
      item.dataset.sig = signature;
      item.dataset.state = step.state;
      item.replaceChildren(
        el("h3", { class: "step-title" }, el("span", { class: "step-n", text: String(index + 1) }), step.title),
        el("div", { class: "step-body" }, ...step.build().filter(Boolean)),
      );
    }
  });
}

// ---- partes 2 y 3: los ataques -----------------------------------------------------------------------------------------------

function verdictBadge(item, result) {
  if (item.group === "limit") {
    return result.held ? el("span", { class: "badge", "data-tone": "good", text: "Cubierto" }) : el("span", { class: "badge", "data-tone": "limit", text: "Límite conocido" });
  }
  return result.held ? el("span", { class: "badge", "data-tone": "good", text: "La API lo frenó" }) : el("span", { class: "badge", "data-tone": "bad", text: "La API no lo frenó" });
}

function resultView(item, result) {
  return el("div", { class: "result" },
    el("div", { class: "verdict" }, verdictBadge(item, result), el("strong", { text: result.headline })),
    // Los roles explícitos mantienen la semántica de tabla cuando, en pantallas angostas, el CSS apila las filas (ver style.css).
    el("div", { class: "table-wrap" }, el("table", { class: "attempts", role: "table" },
      el("thead", { role: "rowgroup" }, el("tr", { role: "row" }, ...["Quién", "Qué hace", "Respuesta de la API"].map((h) => el("th", { role: "columnheader", text: h })))),
      el("tbody", { role: "rowgroup" }, ...result.attempts.map((a) => el("tr", { role: "row" },
        el("td", { role: "cell", text: a.who }),
        el("td", { role: "cell" }, a.what, a.note ? el("span", { class: "attempt-note", text: a.note }) : null),
        el("td", { role: "cell" }, el("span", { class: "code", "data-ok": a.ok ? "true" : "false", text: `${a.status} · ${a.label}` })),
      ))),
    )),
    el("p", { class: "lesson", text: result.lesson }),
    result.watch ? el("p", { class: "watch muted", text: result.watch }) : null,
    result.limit ? el("p", { class: "limit-note", text: result.limit }) : null,
  );
}

function renderCards(list, items, results) {
  items.forEach((item, index) => {
    let node = list.children[index];
    if (!node) {
      node = el("li", { class: "card" });
      list.append(node);
    }
    const result = results[item.id];
    const running = ui.running === item.id;
    const signature = JSON.stringify([item.id, result ? result.ran_at : null, ui.busy, running, noteKey(item.id), ui.data.api_ready]);
    if (node.dataset.sig === signature) return;
    node.dataset.sig = signature;
    node.dataset.group = item.group;
    node.dataset.verdict = result && result.held ? "held" : "open";
    node.replaceChildren(
      el("h3", { text: item.title }),
      el("div", { class: "card-body" },
        el("p", { text: item.what }),
        el("div", { class: "actions" },
          button(running ? "Probando…" : result ? "Probar de nuevo" : "Probar este ataque", () => runAttack(item.id),
            { attack: !result, disabled: !ui.data.api_ready })),
        note(item.id),
        result ? resultView(item, result) : null,
      ),
    );
  });
}

// ---- panel lateral ---------------------------------------------------------------------------------------------------------------

function renderActors(d) {
  const customer = d.customer;
  const actors = [
    { tone: "customer", name: "Cliente de práctica", detail: customer ? customer.email : "todavía sin cuenta", status: customer ? (customer.session === "active" ? "sesión abierta" : "sesión cerrada") : "" },
    { tone: "admin", name: "Administración", detail: d.admin_email, status: "cuenta de práctica; su contraseña no se muestra" },
    { tone: "attacker", name: "Atacante", detail: "desde direcciones de práctica", status: "sin cuenta ni permisos" },
    { tone: "target", name: "Cuenta atacada", detail: d.target_email, status: "nadie conoce su contraseña" },
  ];
  const signature = JSON.stringify(actors);
  const list = $("#actors");
  if (list.dataset.sig === signature) return;
  list.dataset.sig = signature;
  list.replaceChildren(...actors.map((actor) =>
    el("li", { "data-tone": actor.tone },
      el("strong", { text: actor.name }),
      el("span", { class: "mono", text: actor.detail }),
      actor.status ? el("span", { class: "muted", text: actor.status }) : null)));
}

function renderEvents(events) {
  const list = $("#events");
  const signature = events.length ? String(events[events.length - 1].n) : "";
  if (list.dataset.sig === signature) return;
  list.dataset.sig = signature;
  if (!events.length) {
    list.replaceChildren(el("li", { class: "empty", text: "Todavía no pasó nada. Empezar por el paso 1." }));
    return;
  }
  list.replaceChildren(...[...events].reverse().map((event) =>
    el("li", { class: "entry", "data-ok": event.ok ? "true" : "false" },
      el("span", { class: "time", text: formatTime(event.t) }),
      el("p", { text: event.text }),
      event.detail ? el("p", { class: "muted", text: event.detail }) : null)));
}

function renderServerLog(lines) {
  const list = $("#serverlog");
  const signature = JSON.stringify(lines);
  if (list.dataset.sig === signature) return;
  list.dataset.sig = signature;
  if (!lines.length) {
    list.replaceChildren(el("li", { class: "empty", text: "Todavía no hay movimiento." }));
    return;
  }
  list.replaceChildren(...[...lines].reverse().map((line) =>
    el("li", { "data-level": line.level },
      el("span", { class: "when", text: line.t ? formatTime(line.t) : "" }),
      el("span", { class: "level", text: (LEVEL_LABEL[line.level] || line.level).toUpperCase() }),
      el("span", { class: "text", text: line.text }))));
}

// ---- dibujo ------------------------------------------------------------------------------------------------------------------------

function render() {
  const d = ui.data;
  if (!d) return;
  renderSteps(d);
  renderCards($("#attacks"), d.catalog.filter((item) => item.group === "defended"), d.results);
  renderCards($("#limits"), d.catalog.filter((item) => item.group === "limit"), d.results);
  renderActors(d);
  renderEvents(d.events);
  renderServerLog(d.log);
}

// ---- reinicio ----------------------------------------------------------------------------------------------------------------------

$("#reset").addEventListener("click", async (event) => {
  const node = event.currentTarget;
  if (!ui.resetArmed) {   // dos clics: no se borra el recorrido por un toque sin querer
    ui.resetArmed = true;
    node.textContent = "¿Seguro? Se borra el recorrido y los resultados. Tocar otra vez para confirmar";
    setTimeout(() => { ui.resetArmed = false; node.textContent = "Reiniciar el recorrido"; }, 5000);
    return;
  }
  ui.resetArmed = false;
  node.textContent = "Reiniciar el recorrido";
  ui.notes = {};
  await call("POST", "/api/reset");
  await refresh();
});

refresh();
setInterval(refresh, POLL_MS);
