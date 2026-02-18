/**
 * 전수 점검 API 클라이언트
 */

import axios from 'axios';

const API_URL = `http://${window.location.hostname}:8000`;

export type ScanType = 'scan-all' | 'scan' | 'scan-db';

export interface FullScanRequest {
  server_ids: string[];
  scan_type?: ScanType;
}

export interface FullScanResponse {
  job_id: string;
  message: string;
  total_servers: number;
  status: string;
}

export interface ScanProgress {
  job_id: string;
  status: 'queued' | 'running' | 'completed' | 'failed';
  progress: number;
  current_step: number;
  current_server?: string;
  completed_servers: number;
  total_servers: number;
  message: string;
}

export interface TopVulnerableServer {
  server_id: string;
  hostname: string;
  count: number;
}

export interface RiskDistribution {
  low: number;
  medium: number;
  high: number;
}

export interface ScanResult {
  job_id: string;
  company: string;
  total_servers: number;
  scan_duration: string;
  vulnerable_count: number;
  secure_count: number;
  risk_percentage: number;
  top_vulnerable_server?: TopVulnerableServer;
  risk_distribution: RiskDistribution;
  scan_completed_at: string;
}

/**
 * 전수 점검 시작
 */
export async function startFullScan(serverIds: string[], scanType: ScanType = 'scan-all'): Promise<FullScanResponse> {
  const token = localStorage.getItem('access_token');

  const response = await axios.post<FullScanResponse>(
    `${API_URL}/api/scan/full`,
    { server_ids: serverIds, scan_type: scanType },
    {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    }
  );

  return response.data;
}

/**
 * 점검 진행률 조회
 */
export async function getScanProgress(jobId: string): Promise<ScanProgress> {
  const token = localStorage.getItem('access_token');

  const response = await axios.get<ScanProgress>(
    `${API_URL}/api/scan/progress/${jobId}`,
    {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    }
  );

  return response.data;
}

/**
 * 점검 결과 조회
 */
export async function getScanResult(jobId: string): Promise<ScanResult> {
  const token = localStorage.getItem('access_token');

  const response = await axios.get<ScanResult>(
    `${API_URL}/api/scan/result/${jobId}`,
    {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    }
  );

  return response.data;
}

/**
 * 회사의 모든 서버 ID 조회
 */
export async function getAllServerIds(): Promise<string[]> {
  const token = localStorage.getItem('access_token');

  const response = await axios.get<any[]>(
    `${API_URL}/api/assets`,
    {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    }
  );

  return response.data.map((server: any) => server.server_id);
}
