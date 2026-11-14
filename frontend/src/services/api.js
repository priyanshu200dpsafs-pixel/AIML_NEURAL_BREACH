/**
 * Neural Breach SOC Dashboard API & WebSocket Service
 * Communicates with FastAPI backend endpoints:
 *   - /api/v1/health
 *   - /api/v1/stats
 *   - /api/v1/alerts
 *   - /api/v1/alerts/{alert_id}
 *   - /api/v1/predict
 *   - /api/v1/alerts/simulate
 *   - /api/v1/auth/*
 *   - /ws/alerts
 */

const API_BASE = window.location.origin;

// Session token handling
export const getAuthToken = () => localStorage.getItem('nb_access_token');
export const setAuthToken = (token) => {
  if (token) localStorage.setItem('nb_access_token', token);
  else localStorage.removeItem('nb_access_token');
};

export const getSessionUser = () => {
  const user = localStorage.getItem('nb_session_user');
  if (!user) return null;
  try {
    return JSON.parse(user);
  } catch (e) {
    return null;
  }
};

export const setSessionUser = (user) => {
  if (user) localStorage.setItem('nb_session_user', JSON.stringify(user));
  else localStorage.removeItem('nb_session_user');
};

async function apiRequest(endpoint, options = {}) {
  const url = `${API_BASE}${endpoint}`;
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {})
  };

  const token = getAuthToken();
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const response = await fetch(url, { ...options, headers });
  
  if (!response.ok) {
    let errorDetail = response.statusText;
    try {
      const errJson = await response.json();
      errorDetail = errJson.detail || errJson.error || errJson.message || JSON.stringify(errJson);
    } catch (_) {}
    const err = new Error(typeof errorDetail === 'object' ? JSON.stringify(errorDetail) : errorDetail);
    err.status = response.status;
    throw err;
  }

  // Handle 204 No Content
  if (response.status === 204) return null;
  return await response.json();
}

export const api = {
  // 1. Health & Provenance
  getHealth: () => apiRequest('/api/v1/health'),
  
  // 2. Telemetry & SOC Statistics
  getStats: () => apiRequest('/api/v1/stats'),
  
  // 3. Historical / Filtered Alerts
  getAlerts: (params = {}) => {
    const q = new URLSearchParams();
    if (params.threat_level) q.append('threat_level', params.threat_level);
    if (params.attack_category) q.append('attack_category', params.attack_category);
    if (params.min_score !== undefined && params.min_score !== null) q.append('min_score', params.min_score);
    if (params.limit) q.append('limit', params.limit);
    if (params.offset !== undefined) q.append('offset', params.offset);
    return apiRequest(`/api/v1/alerts?${q.toString()}`);
  },

  // 4. Single Alert by ID
  getAlertById: (alertId) => apiRequest(`/api/v1/alerts/${alertId}`),

  // 5. Real-Time Model Inference (with SHAP/LIME XAI)
  predictFlows: (payload) => apiRequest('/api/v1/predict', {
    method: 'POST',
    body: JSON.stringify(payload)
  }),

  // 6. Benchmark Stream Simulation
  simulateStream: (payload) => apiRequest('/api/v1/alerts/simulate', {
    method: 'POST',
    body: JSON.stringify(payload)
  }),

  // 7. Multi-Tenant Platform Auth
  login: (email, password) => apiRequest('/api/v1/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password })
  }),

  register: (email, password, org_name, display_name) => apiRequest('/api/v1/auth/register', {
    method: 'POST',
    body: JSON.stringify({ email, password, org_name, display_name })
  }),

  getMe: () => apiRequest('/api/v1/auth/me'),

  logout: () => apiRequest('/api/v1/auth/logout', { method: 'POST' }),

  // 8. DB Readiness Probe
  getReady: () => apiRequest('/api/v1/ready').catch(() => ({ status: 'standalone_mode' }))
};

/**
 * Robust WebSocket Alert Stream Client
 */
export class AlertWebSocket {
  constructor(onAlert, onStatusChange) {
    this.onAlert = onAlert;
    this.onStatusChange = onStatusChange;
    this.ws = null;
    this.reconnectTimer = null;
    this.pingTimer = null;
    this.shouldReconnect = true;
  }

  connect() {
    this.shouldReconnect = true;
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/alerts`;

    try {
      this.ws = new WebSocket(wsUrl);

      this.ws.onopen = () => {
        if (this.onStatusChange) this.onStatusChange('CONNECTED');
        this.startHeartbeat();
      };

      this.ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.event === 'CONNECTED') {
            if (this.onStatusChange) this.onStatusChange('CONNECTED', data);
          } else if (data.event === 'PONG') {
            // Heartbeat ACK
          } else if (this.onAlert) {
            this.onAlert(data);
          }
        } catch (err) {
          console.warn('[WS] Non-JSON payload received:', event.data);
        }
      };

      this.ws.onerror = (err) => {
        if (this.onStatusChange) this.onStatusChange('ERROR');
      };

      this.ws.onclose = () => {
        this.stopHeartbeat();
        if (this.onStatusChange) this.onStatusChange('DISCONNECTED');
        if (this.shouldReconnect) {
          this.reconnectTimer = setTimeout(() => this.connect(), 3000);
        }
      };
    } catch (e) {
      if (this.onStatusChange) this.onStatusChange('ERROR');
      if (this.shouldReconnect) {
        this.reconnectTimer = setTimeout(() => this.connect(), 3000);
      }
    }
  }

  startHeartbeat() {
    this.stopHeartbeat();
    this.pingTimer = setInterval(() => {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.send('ping');
      }
    }, 15000);
  }

  stopHeartbeat() {
    if (this.pingTimer) {
      clearInterval(this.pingTimer);
      this.pingTimer = null;
    }
  }

  disconnect() {
    this.shouldReconnect = false;
    this.stopHeartbeat();
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }
}

