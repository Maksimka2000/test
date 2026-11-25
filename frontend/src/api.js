async function request(path, options = {}) {
  const { headers: optionHeaders, ...rest } = options;
  const headers = { Accept: "application/json", ...optionHeaders };
  if (rest.body instanceof FormData) {
    delete headers["Content-Type"];
  }
  let response;
  try {
    response = await fetch(`/api${path}`, {
      cache: "no-store",
      ...rest,
      headers,
    });
  } catch {
    const error = new Error("The API is not reachable.");
    error.payload = { detail: "The API is not reachable." };
    throw error;
  }

  const text = await response.text();
  let body = null;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = { detail: text };
    }
  }
  if (!response.ok) {
    const error = new Error("Request failed");
    error.status = response.status;
    error.payload = body;
    throw error;
  }
  return body;
}

export function getHealth() {
  return request("/health");
}

export function createJob(formData) {
  return request("/jobs", { method: "POST", body: formData });
}

export function getJob(id) {
  return request(`/jobs/${id}`);
}

export function getQueue() {
  return request("/queue");
}

export function retryAllFailed() {
  return request("/queue/retry-failed", { method: "POST" });
}

export function retryJob(id) {
  return request(`/jobs/${id}/retry-failed`, { method: "POST" });
}

export function pauseJob(id) {
  return request(`/jobs/${id}/pause`, { method: "POST" });
}

export function resumeJob(id) {
  return request(`/jobs/${id}/resume`, { method: "POST" });
}

export function skipTarget(id) {
  return request(`/targets/${id}/skip`, { method: "POST" });
}

export function retryTarget(id) {
  return request(`/targets/${id}/retry`, { method: "POST" });
}

export function messagesFrom(error) {
  const detail = error.payload && error.payload.detail;
  if (typeof detail === "string" && detail.trim()) {
    return [detail];
  }
  if (Array.isArray(detail)) {
    return detail.map((item) => {
      if (!item || typeof item === "string") {
        return String(item);
      }
      const loc = Array.isArray(item.loc) ? item.loc.filter((part) => part !== "body") : [];
      const message = item.msg || "Invalid value.";
      if (loc[0] === "targets" && typeof loc[1] === "number") {
        return `Line ${loc[1]}: ${message}`;
      }
      return message;
    });
  }
  return ["The API is not reachable."];
}
