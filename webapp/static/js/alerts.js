import { api } from "./api.js";
import {
  $,
  badge,
  configurePagination,
  createPoller,
  element,
  endpoint,
  formatDate,
  formatNumber,
  replaceChildren,
  setPanelState,
  setText,
  showAlertDetails,
} from "./utils.js";

const state = { limit: 25, offset: 0 };
const updatePagination = configurePagination($("#alert-pagination"), state, refreshAlerts);

function cell(value) {
  return element("td", "", value ?? "—");
}

function query() {
  return {
    limit: state.limit,
    offset: state.offset,
    severity: $("#alert-severity").value || undefined,
    rule_id: $("#alert-rule").value || undefined,
    status: $("#alert-status").value || undefined,
    process: $("#alert-process").value.trim() || undefined,
  };
}

function renderSummary(summary) {
  const statuses = summary.status_counts || {};
  const severities = summary.active_severity_counts || {};
  setText("#alert-row-total", formatNumber(summary.alert_rows));
  setText("#alert-occurrence-total", formatNumber(summary.total_occurrences));
  setText("#alert-new-total", formatNumber(statuses.new || 0));
  setText("#alert-ack-total", formatNumber(statuses.acknowledged || 0));
  setText("#alert-resolved-total", formatNumber(statuses.resolved || 0));
  setText("#alert-ignored-total", formatNumber(statuses.ignored || 0));
  setText("#alert-high-total", formatNumber(severities.HIGH || 0));
  setText("#alert-medium-total", formatNumber(severities.MEDIUM || 0));
  setText("#alert-low-total", formatNumber(severities.LOW || 0));
}

async function changeStatus(alertId, status, button) {
  button.disabled = true;
  try {
    await api.setAlertStatus(alertId, status);
    await refreshAlerts();
    document.dispatchEvent(new CustomEvent("netguard:risk-refresh"));
  } catch (error) {
    setPanelState("alerts", "error", error.message);
  }
}

async function refreshAlerts() {
  setPanelState("alerts", "loading", "Loading alerts…");
  try {
    const parameters = query();
    const [result, summary] = await Promise.all([
      api.alerts(parameters),
      api.alertSummary(),
    ]);
    const alerts = result.items || [];
    renderSummary(summary);
    updatePagination(alerts.length);
    if (!alerts.length) {
      $("#alerts-content").hidden = true;
      setPanelState("alerts", "empty", "No alerts match the selected filters for the Current Session.");
      return;
    }
    const rows = alerts.map((alert) => {
      const row = element("tr");
      const severity = element("td");
      severity.append(badge(alert.severity, "severity"));
      const type = element("td");
      const title = element("strong", "alert-title", alert.display_title || "Unusual Network Activity");
      title.title = alert.description || "Open Details to review this incident.";
      type.append(title);
      const status = element("td");
      const lifecycle = alert.status || (alert.acknowledged ? "acknowledged" : "new");
      const statusLabel = lifecycle === "new" && (alert.occurrence_count || 1) > 1
        ? "Repeated alert"
        : lifecycle;
      status.append(badge(statusLabel));
      const actions = element("td", "table-actions");
      const details = element("button", "button button--secondary button--small", "Details");
      details.type = "button";
      details.addEventListener("click", () => showAlertDetails(alert));
      actions.append(details);
      if (alert.id) {
        const transitions = lifecycle === "new"
          ? [["acknowledged", "Acknowledge"], ["resolved", "Resolve"], ["ignored", "Ignore"]]
          : lifecycle === "acknowledged"
            ? [["resolved", "Resolve"], ["ignored", "Ignore"]]
            : [["new", "Reopen"]];
        transitions.forEach(([next, label]) => {
          const action = element("button", "button button--secondary button--small", label);
          action.type = "button";
          action.addEventListener("click", () => changeStatus(alert.id, next, action));
          actions.append(action);
        });
      }
      row.append(
        cell(formatDate(alert.last_seen || alert.timestamp)),
        severity,
        type,
        cell(alert.process_name || "Unknown application"),
        cell(endpoint(alert.source_ip, alert.source_port)),
        cell(endpoint(alert.target_ip || alert.destination_ip, alert.destination_port)),
        cell(formatNumber(alert.occurrence_count || 1)),
        status,
        actions,
      );
      return row;
    });
    replaceChildren($("#alerts-body"), rows);
    const openAlert = alerts.find((alert) => alert.id === window.netguardOpenAlertId);
    if (openAlert) showAlertDetails(openAlert, { focus: false });
    $("#alerts-content").hidden = false;
    setPanelState("alerts", "ready");
  } catch (error) {
    $("#alerts-content").hidden = true;
    setPanelState("alerts", "error", error.message);
  }
}

$("#alert-filters").addEventListener("submit", (event) => {
  event.preventDefault();
  state.limit = Number($("#alert-page-size").value);
  state.offset = 0;
  refreshAlerts();
});
$("#alert-clear").addEventListener("click", () => {
  ["#alert-severity", "#alert-rule", "#alert-status", "#alert-process"].forEach((selector) => {
    $(selector).value = "";
  });
  $("#alert-page-size").value = "25";
  state.limit = 25;
  state.offset = 0;
  refreshAlerts();
});

createPoller(refreshAlerts, 3000);
