const csrfToken = document.querySelector('meta[name="netguard-csrf-token"]')?.content || "";

export class ApiError extends Error {
  constructor(code, message, status = 0) {
    super(message);
    this.name = "ApiError";
    this.code = code;
    this.status = status;
  }
}

let consecutiveFailures = 0;

function publishApiState(available, error = null) {
  if (available) {
    consecutiveFailures = 0;
  } else {
    consecutiveFailures += 1;
  }
  document.dispatchEvent(new CustomEvent("netguard:api-state", {
    detail: { available, consecutiveFailures, error },
  }));
}

async function request(path, options = {}) {
  const method = options.method || "GET";
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), options.timeout || 8000);
  const headers = { Accept: "application/json", ...(options.headers || {}) };
  if (method !== "GET" && method !== "HEAD") {
    headers["X-NetGuard-CSRF-Token"] = csrfToken;
  }
  let body;
  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(options.body);
  }
  const abortFromCaller = () => controller.abort();
  options.signal?.addEventListener("abort", abortFromCaller, { once: true });
  try {
    const response = await fetch(path, {
      method,
      headers,
      body,
      credentials: "same-origin",
      signal: controller.signal,
    });
    const payload = await response.json().catch(() => null);
    if (!payload || typeof payload.ok !== "boolean") {
      throw new ApiError("MALFORMED_RESPONSE", "The local API returned an invalid response.", response.status);
    }
    if (!payload.ok) {
      throw new ApiError(
        payload.error?.code || "API_ERROR",
        payload.error?.message || "The local API request failed.",
        response.status,
      );
    }
    publishApiState(true);
    return payload.data;
  } catch (error) {
    if (error.name !== "AbortError") {
      publishApiState(false, error);
    }
    throw error;
  } finally {
    window.clearTimeout(timeout);
    options.signal?.removeEventListener("abort", abortFromCaller);
  }
}

async function download(path) {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 30000);
  try {
    const response = await fetch(path, {
      credentials: "same-origin",
      signal: controller.signal,
    });
    if (!response.ok) {
      const payload = await response.json().catch(() => null);
      throw new ApiError(
        payload?.error?.code || "DOWNLOAD_FAILED",
        payload?.error?.message || "The requested download could not be generated.",
        response.status,
      );
    }
    const disposition = response.headers.get("Content-Disposition") || "";
    const match = disposition.match(/filename="?([^";]+)"?/i);
    const filename = match?.[1] || "netguard-download";
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    publishApiState(true);
    return filename;
  } catch (error) {
    if (error.name !== "AbortError") {
      publishApiState(false, error);
    }
    throw error;
  } finally {
    window.clearTimeout(timeout);
  }
}

function query(parameters = {}) {
  const values = new URLSearchParams();
  Object.entries(parameters).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== "") {
      values.set(key, String(value));
    }
  });
  const encoded = values.toString();
  return encoded ? `?${encoded}` : "";
}

export const api = {
  status: (options) => request("/api/v1/status", options),
  interfaces: (options) => request("/api/v1/interfaces", options),
  statistics: (options) => request("/api/v1/statistics", options),
  packets: (parameters, options) => request(`/api/v1/packets${query(parameters)}`, options),
  alerts: (parameters, options) => request(`/api/v1/alerts${query(parameters)}`, options),
  connections: (parameters, options) => request(`/api/v1/connections${query(parameters)}`, options),
  score: (options) => request("/api/v1/security-score", options),
  risk: (options) => request("/api/v1/risk", options),
  alertSummary: (options) => request("/api/v1/alerts/summary", options),
  baselineStatus: (options) => request("/api/v1/baseline-status", options),
  processConnections: (options) => request("/api/v1/process-connections", options),
  currentSession: (options) => request("/api/v1/current-session", options),
  health: (options) => request("/api/v1/health", options),
  databaseSummary: (options) => request("/api/v1/database/summary", options),
  startCapture: (interfaceId, developmentMode) => request("/api/v1/capture/start", {
    method: "POST",
    body: { interface_id: interfaceId, development_mode: developmentMode },
  }),
  stopCapture: () => request("/api/v1/capture/stop", { method: "POST", body: {} }),
  acknowledge: (alertId) => request(`/api/v1/alerts/${alertId}/acknowledge`, { method: "POST" }),
  setAlertStatus: (alertId, status) => request(`/api/v1/alerts/${alertId}/status`, {
    method: "POST",
    body: { status },
  }),
  downloadCsv: (type) => download(`/api/v1/current-session/export/csv${query({ type })}`),
  downloadPdf: () => download("/api/v1/current-session/report/pdf"),
};
