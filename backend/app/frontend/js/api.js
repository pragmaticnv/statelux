/**
 * STATEFLUX — API Client Layer
 * Centralized, typed-like promise-based client for all backend endpoints.
 * Never throws raw unhandled exceptions; returns structured error payloads if offline.
 */
// Same-origin API routing for both Vercel production and local web server
const API_BASE = (typeof window !== 'undefined' && window.location && window.location.protocol.startsWith('http'))
  ? '/api/v1'
  : 'http://127.0.0.1:8000/api/v1';

class StatefluxAPI {
  constructor(baseUrl = API_BASE) {
    this.baseUrl = baseUrl;
  }

  async request(endpoint, options = {}) {
    const url = `${this.baseUrl}${endpoint}`;
    const defaultHeaders = {
      'Accept': 'application/json',
      'Content-Type': 'application/json'
    };

    try {
      const response = await fetch(url, {
        ...options,
        headers: {
          ...defaultHeaders,
          ...options.headers
        }
      });

      if (!response.ok) {
        let errBody;
        try {
          errBody = await response.json();
        } catch (_) {
          errBody = { detail: response.statusText };
        }
        return {
          ok: false,
          status: response.status,
          error: errBody.detail || `UNAVAILABLE (HTTP ${response.status})`
        };
      }

      // Handle text vs json
      const contentType = response.headers.get('content-type') || '';
      if (contentType.includes('application/json')) {
        const data = await response.json();
        return { ok: true, status: response.status, data };
      } else {
        const text = await response.text();
        return { ok: true, status: response.status, text };
      }
    } catch (err) {
      console.warn(`[STATEFLUX API] Request to ${url} failed:`, err);
      return {
        ok: false,
        status: 0,
        error: `UNAVAILABLE: Service disconnected or timed out (${err.message})`
      };
    }
  }

  // --- HEALTH & STATUS ---
  async getHealth() {
    return this.request('/health');
  }

  // --- FLEET & INVENTORY ---
  async getFleet() {
    return this.request('/fleet');
  }

  async getFleetStats() {
    return this.request('/fleet/stats');
  }

  async getEndpoints() {
    return this.request('/endpoints');
  }

  async getEndpoint(id) {
    return this.request(`/endpoints/${id}`);
  }

  async getTunnels() {
    return this.request('/tunnels');
  }

  async getTunnel(id) {
    return this.request(`/tunnels/${id}`);
  }

  // --- SECURITY & FLOORS ---
  async getSecurityFleet() {
    return this.request('/security/fleet');
  }

  async getSecurityFloors() {
    return this.request('/security/fleet');
  }

  async getSecurityFloor(id) {
    return this.request(`/security/floor/${id}`);
  }

  // --- DIGITAL TWIN ---
  async getTwin() {
    return this.request('/twin');
  }

  async getTwinTunnel(id) {
    return this.request(`/twin/${id}`);
  }

  // --- GRAPH ---
  async getFleetGraph() {
    return this.request('/graph/fleet');
  }

  // --- SIMULATION ---
  async runSimulation(changeRequest) {
    return this.request('/simulations', {
      method: 'POST',
      body: JSON.stringify(changeRequest)
    });
  }

  // --- MIGRATION PLANS ---
  async getMigrationPlan(changeRequest = null) {
    const body = changeRequest ? JSON.stringify(changeRequest) : '{}';
    return this.request('/migrations/plan', {
      method: 'POST',
      body: body
    });
  }

  // --- LAB VALIDATION ---
  async getLabValidation() {
    return this.request('/lab/validation');
  }

  async runLab() {
    return this.request('/lab/run', {
      method: 'POST'
    });
  }

  async getLabResult(scenarioId) {
    return this.request(`/lab/results/${scenarioId}`);
  }

  async getLabLog(scenarioId, logName = 'charon.log') {
    return this.request(`/lab/artifacts/${scenarioId}/${logName}`);
  }

  // --- FINDINGS & EVIDENCE ---
  async getFindings(params = {}) {
    const q = new URLSearchParams();
    if (params.severity) q.append('severity', params.severity);
    if (params.tunnel_id) q.append('tunnel_id', params.tunnel_id);
    if (params.finding_type) q.append('finding_type', params.finding_type);
    const qs = q.toString() ? `?${q.toString()}` : '';
    return this.request(`/findings${qs}`);
  }

  async getFinding(id) {
    return this.request(`/findings/${id}`);
  }

  async getEvidenceList(params = {}) {
    const q = new URLSearchParams();
    if (params.tunnel_id) q.append('tunnel_id', params.tunnel_id);
    if (params.source_type) q.append('source_type', params.source_type);
    const qs = q.toString() ? `?${q.toString()}` : '';
    return this.request(`/evidence${qs}`);
  }

  async getEvidence(id) {
    return this.request(`/evidence/${id}`);
  }

  async getEvidenceChain(findingId) {
    return this.request(`/evidence/chain/${findingId}`);
  }

  // --- GROUNDED AI ---
  async explainFinding(findingId) {
    return this.request('/ai/explain/finding', {
      method: 'POST',
      body: JSON.stringify({ finding_id: findingId })
    });
  }

  async explainChange(changeRequest) {
    return this.request('/ai/explain/change', {
      method: 'POST',
      body: JSON.stringify(changeRequest)
    });
  }

  async askAI(question, context = {}) {
    return this.request('/ai/ask', {
      method: 'POST',
      body: JSON.stringify({ question, ...context })
    });
  }

  // --- REPORTS ---
  async getExecutiveReport() {
    return this.request('/reports/executive', { method: 'POST' });
  }

  async getTechnicalReport() {
    return this.request('/reports/technical', { method: 'POST' });
  }

  async getChangeImpactReport(params = null) {
    let body = '{}';
    if (typeof params === 'string') {
      body = JSON.stringify({ simulation_id: params });
    } else if (params && typeof params === 'object') {
      body = JSON.stringify({ simulation_id: params.simulation_id || null });
    }
    return this.request('/reports/change-impact', { method: 'POST', body });
  }

  async getLabValidationReport() {
    return this.request('/reports/lab-validation', { method: 'POST' });
  }
}

// Global API instance
window.api = new StatefluxAPI();
