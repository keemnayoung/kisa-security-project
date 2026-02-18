/**
 * 자산 분석 API 클라이언트
 */

import axios from 'axios';

const API_URL = `http://${window.location.hostname}:8000`;

export interface AnalysisServer {
  server_id: string;
  hostname: string;
  ip_address: string;
  os_type: string;
  db_type: string | null;
  is_active: boolean;
  secure_count: number;
  vulnerable_count: number;
  exception_count: number;
}

export interface CheckItem {
  item_code: string;
  title: string;
  status: string;
  has_exception: boolean;
  auto_fix: boolean;
  severity: string;
  raw_evidence: string;
  scan_date: string;
  guide: string;
  auto_fix_description: string;
}

export interface RemediationItem {
  item_code: string;
  title: string;
  is_success: boolean;
  failure_reason: string;
  raw_evidence: string;
  action_date: string;
  severity: string;
  auto_fix: boolean;
}

export interface RemediationCategoryResult {
  success_count: number;
  fail_count: number;
  items: RemediationItem[];
}

export interface RemediationResults {
  os_results: { [key: string]: RemediationCategoryResult };
  db_results: { [key: string]: RemediationCategoryResult };
}

export interface CategoryResult {
  secure_count: number;
  vulnerable_count: number;
  exception_count: number;
  items: CheckItem[];
}

export interface ServerResults {
  server_info: {
    server_id: string;
    hostname: string;
    ip_address: string;
    os_type: string;
    db_type: string | null;
    is_active: boolean;
  };
  os_results: { [key: string]: CategoryResult };
  db_results: { [key: string]: CategoryResult };
}

/**
 * 서버 목록 + 양호/취약 개수 조회
 */
export async function getAnalysisServers(): Promise<AnalysisServer[]> {
  const token = localStorage.getItem('access_token');
  const response = await axios.get(`${API_URL}/api/analysis/servers`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  return response.data;
}

/**
 * 서버별 점검 결과 조회
 */
export async function getServerResults(serverId: string): Promise<ServerResults> {
  const token = localStorage.getItem('access_token');
  const response = await axios.get(`${API_URL}/api/analysis/servers/${serverId}/results`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  return response.data;
}

/**
 * 서버별 조치 이력 조회
 */
export async function getRemediationHistory(serverId: string): Promise<RemediationResults> {
  const token = localStorage.getItem('access_token');
  const response = await axios.get(`${API_URL}/api/analysis/servers/${serverId}/remediation`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  return response.data;
}

export interface ScanHistoryItem {
  scan_date: string;
  server_id: string;
  item_code: string;
  title: string;
  status: string;
}

export interface RemediationHistoryItem {
  action_date: string;
  server_id: string;
  item_code: string;
  title: string;
  is_success: boolean;
}

export interface HistoryData {
  scans: ScanHistoryItem[];
  remediations: RemediationHistoryItem[];
}

/**
 * 전체 점검/조치 이력 조회
 */
export async function getHistory(): Promise<HistoryData> {
  const token = localStorage.getItem('access_token');
  const response = await axios.get(`${API_URL}/api/analysis/history`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  return response.data;
}
