// Installability and push notifications. No caching: every request goes to Doorman so nothing stale is ever shown.
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));
self.addEventListener("fetch", () => {});

// Every push that waits for a yes or no has two buttons. The no acts right here; the yes too when the
// push says accept: "tap", otherwise it opens the app at the push's page, as a tap on the push always does.
// iOS shows no buttons; there a tap on the notification opens it.
// A send's approval carries { approval: { id, hash, accept } }.
// Several sends of one task share one push, { approval: { id, ids, accept, hashes } }, under one tag: a
// later one replaces it without buzzing again (no renotify). Deny all refuses them. Accept all approves
// them when each could be accepted from a push of its own; with a warning among them it is Review.
const APPROVAL_ACTIONS = [{ action: "accept", title: "Accept" }, { action: "decline", title: "Deny" }];
const GROUP_ACTIONS = [{ action: "accept", title: "Review" }, { action: "decline", title: "Deny all" }];
const GROUP_TAP_ACTIONS = [{ action: "accept", title: "Accept all" }, { action: "decline", title: "Deny all" }];

// Everything else that waits carries { ask: { kind, id, accept } } (Engine.push_ask): the buttons, the
// app's own call for each, and the line the notification turns into.
const ASKS = {
  network: {
    yes: "Allow once", no: "Deny",
    call: (id, yes) => [`/owner/egress/requests/${id}/decide`, { decision: yes ? "once" : "deny", via: "notification" }],
    done: (yes) => (yes ? ["Allowed once", "It gets through for an hour."] : ["Denied", "The agent hears it can't reach it."]),
  },
  changeset: {
    yes: "Apply all", no: "Deny",
    call: (id, yes) => [`/owner/changesets/${id}/${yes ? "apply" : "reject"}`, { via: "notification" }],
    done: (yes, data) => {
      if (!yes) return ["Denied", "Nothing in it ran."];
      if (data.status !== "applied") return ["Applied in part", "Open Doorman to see what didn't run.", true];
      return ["Applied", data.approval_id ? "What it sends asks you once more." : "See it in the journal."];
    },
  },
  quarantine: {
    yes: "Release", no: "Keep held back",
    call: (id, yes) => [`/owner/quarantine/${id}/${yes ? "release" : "keep"}`, {}],
    done: (yes) => (yes ? ["Released", "Agents can read it now."] : ["Kept held back", "No agent gets it."]),
  },
};

function actionsFor(approval, ask) {
  if (approval) return approval.ids ? (approval.accept === "tap" ? GROUP_TAP_ACTIONS : GROUP_ACTIONS) : APPROVAL_ACTIONS;
  if (ask) return [{ action: "accept", title: ASKS[ask.kind].yes }, { action: "decline", title: ASKS[ask.kind].no }];
  return [];
}

self.addEventListener("push", (event) => {
  let data;
  try { data = event.data ? event.data.json() : {}; } catch (err) { data = { body: event.data.text() }; }
  const approval = data.approval && data.approval.id ? data.approval : null;
  const ask = !approval && data.ask && data.ask.id && ASKS[data.ask.kind] ? data.ask : null;
  event.waitUntil(self.registration.showNotification(data.title || "Doorman", {
    body: data.body || "", tag: data.tag, icon: "icon-192.png", data: { url: data.url || "./", approval, ask },
    actions: actionsFor(approval, ask),
  }));
});

async function openApp(url) {
  const windows = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
  for (const client of windows) {
    try { await client.navigate(url); return await client.focus(); } catch (err) { /* not ours to navigate */ }
  }
  return self.clients.openWindow(url);
}

// Replaces the notification with a short, silent line saying what happened. A tap on it opens the
// approval. Pure confirmations go away on their own after a few seconds.
async function report(tag, title, body, url, vanish) {
  await self.registration.showNotification(title, { body, tag, icon: "icon-192.png", silent: true, data: { url } });
  if (!vanish) return;
  await new Promise((resolve) => setTimeout(resolve, 4000));
  for (const n of await self.registration.getNotifications({ tag })) if (!n.data || !(n.data.approval || n.data.ask)) n.close();
}

// The same call the app makes, with the same session cookie (same origin, so it goes along) and the
// same CSRF header.
async function post(path, body) {
  let response;
  try {
    response = await fetch(path, {
      method: "POST", credentials: "same-origin",
      headers: { "X-Requested-With": "doorman", "Content-Type": "application/json" }, body: JSON.stringify(body),
    });
  } catch (err) {
    return { outcome: "offline" };
  }
  const data = await response.json().catch(() => ({}));
  if (response.ok) return { outcome: "ok", data };
  if (response.status === 401) return { outcome: "login" };
  return { outcome: "refused", code: data.code, reason: data.reason || `HTTP ${response.status}` };
}

// Accept sends the payload hash the push carried: if the payload changed since, Doorman refuses it,
// exactly as for a tap in the app.
function decide(approval, approve) {
  return post(`/owner/approvals/${encodeURIComponent(approval.id)}/decide`,
    approve ? { approve: true, payload_hash: approval.hash, via: "notification" } : { approve: false, via: "notification" });
}

const NEEDS_APP = new Set(["open_app", "reauth", "unauthenticated", "csrf", "invalid"]);

// Where an approved send stands now (no waiting), or null when Doorman can't be asked.
async function results(id) {
  try {
    const response = await fetch(`/owner/approvals/${encodeURIComponent(id)}/results`, {
      credentials: "same-origin", headers: { "X-Requested-With": "doorman" },
    });
    return response.ok ? await response.json() : null;
  } catch (err) {
    return null;
  }
}

const UNDER_WAY = ["sending", "running"];

// What the send did, once it ended: sent, or open Doorman to see why not.
function outcome(tag, list, url) {
  if (list.every((r) => r.status === "done")) return report(tag, "Approved", "Sent.", url, true);
  if (list.some((r) => r.status === "unknown")) {
    return report(tag, "Approved, but it may not have gone out", "Open Doorman before you send it again.", url, false);
  }
  return report(tag, "Approved, but not sent", "Open Doorman to see what happened.", url, false);
}

// Deny all or Accept all on a grouped push: each approval it named, one by one (Accept with that
// approval's own hash). One decided elsewhere in the meantime doesn't stop the others; being offline does,
// and anything else (logged out, a payload that changed) opens the review screen with what is left.
async function decideAll(tag, approval, url, approve) {
  const did = approve ? "Approved" : "Denied";
  const results = [];
  let decided = 0, gone = 0;
  for (const [i, id] of approval.ids.entries()) {
    const answer = await decide({ id, hash: (approval.hashes || [])[i] }, approve);
    if (answer.outcome === "ok") {
      decided += 1;
      results.push(...(answer.data.results || []));
    } else if (answer.outcome === "refused" && ["decided", "expired", "approval"].includes(answer.code)) gone += 1;
    else if (answer.outcome === "offline") {
      return report(tag, "Couldn't reach Doorman", `${decided ? `${did} ${decided}, the rest not decided.` : "Nothing was decided."} Tap to open it.`, url, false);
    } else {
      try { return await openApp(url); } catch (err) {
        return report(tag, "Open Doorman to decide", "Log in to approve or decline these.", url, false);
      }
    }
  }
  if (!decided) return report(tag, "Already decided", "Nothing was changed from here.", url, true);
  const title = decided === 1 ? did : `${did} ${decided === approval.ids.length ? "all " : ""}${decided}`;
  const also = gone ? ` ${gone} had already been decided.` : "";
  if (!approve) return report(tag, title, `Nothing was sent.${also}`, url, !gone);
  if (results.some((r) => r.status !== "done" && !UNDER_WAY.includes(r.status))) {
    return report(tag, `${title}, but not all went out`, "Open Doorman to see what happened.", url, false);
  }
  // one still under way reports by a push of its own, under its own approval's tag
  if (results.some((r) => UNDER_WAY.includes(r.status))) return report(tag, `${title}: sending`, `A notification follows for what is still going out.${also}`, url, !gone);
  return report(tag, title, `Sent.${also}`, url, !gone);
}

// Doorman didn't take the decision: say why, or open the app where that is what it takes.
async function notDone(tag, answer, url) {
  if (answer.outcome === "login" || (answer.outcome === "refused" && NEEDS_APP.has(answer.code))) {
    try { return await openApp(url); } catch (err) {
      return report(tag, "Open Doorman to decide", "Log in to approve or decline this.", url, false);
    }
  }
  if (answer.outcome === "offline") return report(tag, "Couldn't reach Doorman", "Nothing was decided. Tap to open it.", url, false);
  if (answer.code === "decided") return report(tag, "Already decided", answer.reason, url, true);
  if (answer.code === "expired") return report(tag, "Expired", "Nothing was sent.", url, true);
  if (answer.code === "payload_changed") return report(tag, "Changed since this notification", "Nothing was sent. Tap to look at it again.", url, false);
  return report(tag, "Not done", answer.reason, url, false);
}

async function act(notification, approve) {
  const { url = "./", approval } = notification.data || {};
  const tag = notification.tag || `approval-${approval.id}`;
  // A passkey, a payment, a warning: approve on the approval screen, not from here.
  if (approve && approval.accept !== "tap") return openApp(url);
  if (approval.ids) return decideAll(tag, approval, url, approve);
  const answer = await decide(approval, approve);
  if (answer.outcome !== "ok") return notDone(tag, answer, url);
  const list = answer.data.results || [];
  if (!approve) return report(tag, "Denied", "Nothing was sent.", url, true);
  if (!list.some((r) => UNDER_WAY.includes(r.status))) return outcome(tag, list, url);
  // Doorman answered after about 3 s with the send still under way (a big upload): its outcome comes as a
  // push under this tag. Asked once more after this line is up, in case that push was quicker than it.
  await report(tag, "Approved: sending", "A notification follows when it's out.", url, false);
  const now = await results(approval.id);
  if (now && now.done) return outcome(tag, now.results, url);
  return undefined;
}

// A button on a push that isn't a send's approval (ASKS): a network request, a changeset, an item held back.
async function answerAsk(notification, yes) {
  const { url = "./", ask } = notification.data || {};
  const kind = ASKS[ask.kind];
  const tag = notification.tag || `${ask.kind}-${ask.id}`;
  if (yes && ask.accept !== "tap") return openApp(url);
  const answer = await post(...kind.call(encodeURIComponent(ask.id), yes));
  if (answer.outcome === "ok") {
    const [title, body, stay] = kind.done(yes, answer.data || {});
    return report(tag, title, body, url, !stay);
  }
  // decided in the app or on another device, or run out, since the push came
  if (answer.outcome === "refused" && (["not_found", "changeset"].includes(answer.code) || /already/.test(answer.reason))) {
    return report(tag, "No longer open", "It was decided or ran out before this. Nothing was changed.", url, true);
  }
  return notDone(tag, answer, url);
}

// A tap on the body (or on a platform without buttons, where event.action is empty or missing) opens
// the app at the notification's page, e.g. the approval it asks for.
self.addEventListener("notificationclick", (event) => {
  const notification = event.notification;
  const { url = "./", approval, ask } = notification.data || {};
  const action = event.action || "";
  notification.close();
  if ((approval || ask) && (action === "accept" || action === "decline")) {
    event.waitUntil((approval ? act : answerAsk)(notification, action === "accept"));
    return;
  }
  event.waitUntil(openApp(url));
});
