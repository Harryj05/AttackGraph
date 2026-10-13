import type { Scan, GraphData, Evidence, AgentLog, HumanReviewResponse, ReplayEvent, CalibrationReport } from '../types';

const API_BASE_URL = 'http://127.0.0.1:8000';
const API_KEY = (import.meta as any).env?.VITE_API_KEY || 'attackgraph-insecure-dev-key';

function getHeaders(extraHeaders: Record<string, string> = {}): Record<string, string> {
  return {
    'X-API-Key': API_KEY,
    ...extraHeaders,
  };
}

export async function fetchScans(): Promise<Scan[]> {
  const res = await fetch(`${API_BASE_URL}/scans`, {
    headers: getHeaders(),
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch scans: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchGlobalCalibration(): Promise<CalibrationReport> {
  const res = await fetch(`${API_BASE_URL}/calibration`, {
    headers: getHeaders(),
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch global calibration: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchScanCalibration(scanId: string): Promise<CalibrationReport> {
  const res = await fetch(`${API_BASE_URL}/scans/${scanId}/calibration`, {
    headers: getHeaders(),
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch scan calibration for ${scanId}: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchScanGraph(scanId: string): Promise<GraphData> {
  const res = await fetch(`${API_BASE_URL}/scans/${scanId}/graph`, {
    headers: getHeaders(),
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch graph for scan ${scanId}: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchReplayEvents(scanId: string): Promise<ReplayEvent[]> {
  const res = await fetch(`${API_BASE_URL}/scans/${scanId}/replay`, {
    headers: getHeaders(),
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch replay events for scan ${scanId}: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchNodeEvidence(scanId: string, nodeId: string): Promise<Evidence[]> {
  const res = await fetch(`${API_BASE_URL}/scans/${scanId}/nodes/${nodeId}/evidence`, {
    headers: getHeaders(),
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch evidence for node ${nodeId}: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchAgentLog(scanId: string): Promise<AgentLog[]> {
  const res = await fetch(`${API_BASE_URL}/scans/${scanId}/agent-log`, {
    headers: getHeaders(),
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch agent log for scan ${scanId}: ${res.statusText}`);
  }
  return res.json();
}

export async function submitHumanReview(
  scanId: string,
  edgeId: string,
  decision: 'confirm' | 'refute',
  reviewer: string = 'human_reviewer',
  reason: string = 'Reviewed via frontend inspector'
): Promise<HumanReviewResponse> {
  const res = await fetch(`${API_BASE_URL}/scans/${scanId}/edges/${edgeId}/human-review`, {
    method: 'POST',
    headers: getHeaders({
      'Content-Type': 'application/json',
    }),
    body: JSON.stringify({
      decision,
      reviewer,
      reason,
    }),
  });
  if (!res.ok) {
    throw new Error(`Failed to submit human review: ${res.statusText}`);
  }
  return res.json();
}

export async function reverifyEdge(scanId: string, edgeId: string): Promise<any> {
  const res = await fetch(`${API_BASE_URL}/scans/${scanId}/edges/${edgeId}/reverify`, {
    method: 'POST',
    headers: getHeaders({
      'Content-Type': 'application/json',
    }),
  });
  if (!res.ok) {
    const errBody = await res.json().catch(() => ({}));
    throw new Error(errBody.detail || `Re-verification failed with status ${res.status}`);
  }
  return res.json();
}

export async function runAgent(scanId: string, maxSteps: number = 15, mode: string = 'agent'): Promise<any> {
  const res = await fetch(`${API_BASE_URL}/scans/${scanId}/agent/run?max_steps=${maxSteps}&mode=${mode}`, {
    method: 'POST',
    headers: getHeaders({
      'Content-Type': 'application/json',
    }),
    body: JSON.stringify({ max_steps: maxSteps, mode }),
  });
  if (!res.ok) {
    const errBody = await res.json().catch(() => ({}));
    throw new Error(errBody.detail || `Agent execution stopped: status ${res.status}`);
  }
  return res.json();
}

export async function createScan(targetUrl: string): Promise<Scan> {
  const res = await fetch(`${API_BASE_URL}/scans`, {
    method: 'POST',
    headers: getHeaders({
      'Content-Type': 'application/json',
    }),
    body: JSON.stringify({ target_url: targetUrl }),
  });
  if (!res.ok) {
    const errBody = await res.json().catch(() => ({}));
    throw new Error(errBody.detail || `Failed to create scan for ${targetUrl}`);
  }
  return res.json();
}

export async function downloadExportReport(scanId: string, format: 'sarif' | 'pdf'): Promise<void> {
  const res = await fetch(`${API_BASE_URL}/scans/${scanId}/export/${format}`, {
    method: 'GET',
    headers: getHeaders(),
  });
  if (!res.ok) {
    const errText = await res.text().catch(() => '');
    throw new Error(`Failed to download ${format.toUpperCase()} report: ${res.statusText} ${errText}`);
  }
  const blob = await res.blob();
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `attackgraph_scan_${scanId.slice(0, 8)}.${format === 'sarif' ? 'sarif' : 'pdf'}`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  window.URL.revokeObjectURL(url);
}

// Deprecated: Kept for backwards compatibility if needed, but downloads should use downloadExportReport
export function getExportSarifUrl(scanId: string): string {
  return `${API_BASE_URL}/scans/${scanId}/export/sarif`;
}

export function getExportPdfUrl(scanId: string): string {
  return `${API_BASE_URL}/scans/${scanId}/export/pdf`;
}

