import { api } from "./api.js";
import {
  $,
  createPoller,
  formatNumber,
  formatTime,
  preference,
  safetyScoreFromRisk,
  setText,
} from "./utils.js";

const body = document.body;
const collapseButton = $("#sidebar-collapse");
const mobileButton = $("#mobile-menu");
const scrim = $("#drawer-scrim");
const sidebarPreference = preference("sidebarCollapsed", "false") === "true";
if (sidebarPreference) body.classList.add("sidebar-collapsed");

function closeDrawer() {
  body.classList.remove("drawer-open");
  mobileButton?.setAttribute("aria-expanded", "false");
}

collapseButton?.addEventListener("click", () => {
  body.classList.toggle("sidebar-collapsed");
  const collapsed = body.classList.contains("sidebar-collapsed");
  localStorage.setItem("netguard.sidebarCollapsed", String(collapsed));
  collapseButton.setAttribute("aria-label", collapsed ? "Expand sidebar" : "Collapse sidebar");
  collapseButton.title = collapsed ? "Expand sidebar" : "Collapse sidebar";
});

mobileButton?.addEventListener("click", () => {
  const open = body.classList.toggle("drawer-open");
  mobileButton.setAttribute("aria-expanded", String(open));
});
scrim?.addEventListener("click", closeDrawer);
document.querySelectorAll(".nav-link").forEach((link) => link.addEventListener("click", closeDrawer));

function statusTone(state) {
  if (state === "running") return "success";
  if (state === "starting" || state === "stopping" || state === "shutting_down") return "warning";
  if (state === "error") return "danger";
  return "unknown";
}

function updateStatus(status) {
  window.netguardStatus = status;
  const state = status?.state || "unknown";
  const tone = statusTone(state);
  const badge = $("#top-capture-status");
  if (badge) {
    badge.textContent = state;
    badge.className = `status-badge status-badge--${tone}`;
  }
  document.dispatchEvent(new CustomEvent("netguard:status", { detail: status }));
}

const shellInterval = Math.max(1500, Number(preference("pollingInterval", "2000")) || 2000);
createPoller(async () => updateStatus(await api.status()), shellInterval);
createPoller(async () => {
  const sessionId = window.netguardStatus?.active_session_id || null;
  const risk = await api.risk();
  setText("#top-safety-score", `${formatNumber(safetyScoreFromRisk(risk?.percentage) ?? 100)}%`);
}, Math.max(5000, shellInterval * 2));
document.addEventListener("netguard:risk-refresh", async () => {
  const sessionId = window.netguardStatus?.active_session_id || null;
  const risk = await api.risk();
  setText("#top-safety-score", `${formatNumber(safetyScoreFromRisk(risk?.percentage) ?? 100)}%`);
});

api.interfaces().then((interfaces) => {
  window.netguardInterfaceNames = Object.fromEntries(
    interfaces.map((item) => [
      item.device,
      item.friendly_name || item.label || "Network adapter",
    ]),
  );
}).catch(() => {
  window.netguardInterfaceNames = {};
});

window.setInterval(() => setText("#top-clock", formatTime(new Date().toISOString())), 1000);
setText("#top-clock", formatTime(new Date().toISOString()));

document.addEventListener("netguard:api-state", (event) => {
  const banner = $("#api-banner");
  if (!banner) return;
  banner.hidden = event.detail.available || event.detail.consecutiveFailures < 3;
});

const modal = $("#details-modal");
const closeModal = () => {
  if (modal) modal.hidden = true;
  window.netguardOpenAlertId = null;
  window.netguardModalReturnFocus?.focus?.();
};
$("#modal-close")?.addEventListener("click", closeModal);
modal?.addEventListener("click", (event) => {
  if (event.target === modal) closeModal();
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && modal && !modal.hidden) closeModal();
  if (event.key === "Escape" && body.classList.contains("drawer-open")) {
    closeDrawer();
  }
  if (event.key === "Tab" && modal && !modal.hidden) {
    const focusable = [
      ...modal.querySelectorAll(
        "button, a, input, select, [tabindex]:not([tabindex='-1'])",
      ),
    ].filter((node) => !node.disabled && !node.hidden);
    if (!focusable.length) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }
});
