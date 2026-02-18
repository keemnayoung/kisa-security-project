/**
 * 자동조치 API 클라이언트
 */

import axios from 'axios';

const API_URL = `http://${window.location.hostname}:8000`;

export interface FixResponse {
  job_id: string;
  total_items: number;
  status: string;
  message: string;
}

export interface FixProgress {
  job_id: string;
  status: 'queued' | 'running' | 'completed' | 'failed';
  progress: number;
  message: string;
  total_items: number;
}

export interface FixResultItem {
  item_code: string;
  title: string;
  is_success: boolean;
  failure_reason?: string;
  raw_evidence: string;
  action_date: string;
}

export interface FixImprovement {
  before_vuln: number;
  after_vuln: number;
  improved: number;
}

export interface FixResultServer {
  server_id: string;
  hostname: string;
  total_items: number;
  success_count: number;
  fail_count: number;
  items: FixResultItem[];
}

export interface FixResult {
  job_id: string;
  total_items: number;
  success_count: number;
  fail_count: number;
  servers?: FixResultServer[];
  items: FixResultItem[];
  improvement: FixImprovement;
}

export interface AffectedServerInfo {
  server_id: string;
  hostname: string;
  ip_address: string;
  os_type: string;
  vulnerable_items: string[];
  vulnerable_count: number;
}

export interface AffectedServersResponse {
  item_codes: string[];
  servers: AffectedServerInfo[];
  total_servers: number;
  total_fixable: number;
}

/**
 * 자동조치 실행 (단일 서버)
 */
export async function startFix(serverId: string, itemCodes: string[]): Promise<FixResponse> {
  const token = localStorage.getItem('access_token');
  const response = await axios.post<FixResponse>(
    `${API_URL}/api/fix/execute`,
    { server_id: serverId, item_codes: itemCodes },
    { headers: { Authorization: `Bearer ${token}` } }
  );
  return response.data;
}

/**
 * 일괄 자동조치 실행 (다중 서버)
 */
export async function startBatchFix(serverIds: string[], itemCodes: string[]): Promise<FixResponse> {
  const token = localStorage.getItem('access_token');
  const response = await axios.post<FixResponse>(
    `${API_URL}/api/fix/execute-batch`,
    { server_ids: serverIds, item_codes: itemCodes },
    { headers: { Authorization: `Bearer ${token}` } }
  );
  return response.data;
}

/**
 * 영향받는 서버 목록 조회
 */
export async function getAffectedServers(itemCodes: string[]): Promise<AffectedServersResponse> {
  const token = localStorage.getItem('access_token');
  const response = await axios.post<AffectedServersResponse>(
    `${API_URL}/api/fix/affected-servers`,
    { item_codes: itemCodes },
    { headers: { Authorization: `Bearer ${token}` } }
  );
  return response.data;
}

/**
 * 조치 진행률 조회
 */
export async function getFixProgress(jobId: string): Promise<FixProgress> {
  const token = localStorage.getItem('access_token');
  const response = await axios.get<FixProgress>(
    `${API_URL}/api/fix/progress/${jobId}`,
    { headers: { Authorization: `Bearer ${token}` } }
  );
  return response.data;
}

/**
 * 조치 결과 조회
 */
export async function getFixResult(jobId: string): Promise<FixResult> {
  const token = localStorage.getItem('access_token');
  const response = await axios.get<FixResult>(
    `${API_URL}/api/fix/result/${jobId}`,
    { headers: { Authorization: `Bearer ${token}` } }
  );
  return response.data;
}
