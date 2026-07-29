import { api } from "./api.js";
import {
  $,
  badge,
  configurePagination,
  createPoller,
  element,
  formatBytes,
  formatDate,
  preference,
  replaceChildren,
  setPanelState,
  setText,
  tcpFlagsLabel,
} from "./utils.js";

const state = {
  limit: Number(preference("pageSize", "25")) || 25,
  offset: 0,
  itemCount: 0,
};
$("#packet-page-size").value = String(state.limit);
function cell(value) {
  return element("td", "", value ?? "—");
}

function query() {
  return {
    limit: state.limit,
    offset: state.offset,
    direction: $("#packet-direction").value || undefined,
    protocol: $("#packet-protocol").value.trim() || undefined,
  };
}

const updatePagination = configurePagination($("#packet-pagination"), state, refreshPackets);

async function refreshPackets() {
  setPanelState("packets", "loading", "Loading packet records…");
  try {
    const result = await api.packets(query());
    const packets = result.items || [];
    state.itemCount = packets.length;
    updatePagination(packets.length);
    if (!packets.length) {
      $("#packets-content").hidden = true;
      setPanelState("packets", "empty", window.netguardStatus?.state === "stopped"
        ? "Capture has not started or no packet records exist."
        : "No packet records match the selected filters.");
      return;
    }
    const rows = packets.map((packet) => {
      const row = element("tr");
      const direction = element("td");
      direction.append(badge(packet.direction, "direction"));
      row.append(
        cell(formatDate(packet.timestamp)),
        cell(packet.src_ip),
        cell(packet.src_port),
        cell(packet.dst_ip),
        cell(packet.dst_port),
        cell(packet.protocol),
        cell(formatBytes(packet.length)),
        direction,
        cell(packet.ip_version ? `IPv${packet.ip_version}` : "—"),
        (() => {
          const value = element("td");
          value.append(tcpFlagsLabel(packet.tcp_flags));
          return value;
        })(),
      );
      return row;
    });
    replaceChildren($("#packets-body"), rows);
    $("#packets-content").hidden = false;
    setPanelState("packets", "ready");
  } catch (error) {
    $("#packets-content").hidden = true;
    setPanelState("packets", "error", error.message);
  }
}

document.addEventListener("netguard:status", (event) => {
  const status = event.detail;
  setText("#packet-capture-state", status.state);
  setText("#packet-adapter", status.selected_interface || localStorage.getItem("netguard.selectedAdapter"));
});

$("#packet-filters").addEventListener("submit", (event) => {
  event.preventDefault();
  state.limit = Number($("#packet-page-size").value);
  state.offset = 0;
  refreshPackets();
});
$("#packet-clear").addEventListener("click", () => {
  $("#packet-direction").value = "";
  $("#packet-protocol").value = "";
  state.offset = 0;
  refreshPackets();
});

createPoller(refreshPackets, 2000);
