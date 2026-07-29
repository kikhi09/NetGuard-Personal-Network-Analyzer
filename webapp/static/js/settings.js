import { $ } from "./utils.js";

const defaults = {
  developmentModeDefault: "false",
  pollingInterval: "2000",
  pageSize: "25",
  sidebarCollapsed: "false",
};

function load() {
  $("#setting-development-mode").checked = localStorage.getItem("netguard.developmentModeDefault") === "true";
  $("#setting-polling").value = localStorage.getItem("netguard.pollingInterval") || defaults.pollingInterval;
  $("#setting-page-size").value = localStorage.getItem("netguard.pageSize") || defaults.pageSize;
  $("#setting-sidebar").checked = localStorage.getItem("netguard.sidebarCollapsed") === "true";
}

function save() {
  localStorage.setItem("netguard.developmentModeDefault", String($("#setting-development-mode").checked));
  localStorage.setItem("netguard.pollingInterval", $("#setting-polling").value);
  localStorage.setItem("netguard.pageSize", $("#setting-page-size").value);
  localStorage.setItem("netguard.sidebarCollapsed", String($("#setting-sidebar").checked));
  $("#settings-message").textContent = "Preferences saved. Reload pages to apply polling changes.";
}

function reset() {
  Object.entries(defaults).forEach(([key, value]) => localStorage.setItem(`netguard.${key}`, value));
  load();
  $("#settings-message").textContent = "Browser preferences reset to defaults.";
}

$("#settings-save").addEventListener("click", save);
$("#settings-reset").addEventListener("click", reset);
load();
