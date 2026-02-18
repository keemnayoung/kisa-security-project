/**
 * 대시보드 API 클라이언트
 */

import axios from 'axios';

const API_URL = `http://${window.location.hostname}:8000`;

export interface DashboardSummary {
  company: string;
  last_scan_date: string;
  total_servers: number;
  os_info: string;
  db_info: string;
}

export interface CategoryData {
  [key: string]: number;
}

export interface TopServer {
  rank: number;
  server_id: string;
  hostname: string;
  ip_address: string;
  vuln_count: number;
}

export interface RiskDistribution {
  low: number;
  medium: number;
  high: number;
  low_percent: number;
  medium_percent: number;
  high_percent: number;
  total: number;
}

export interface VulnerabilityRatio {
  vulnerable: number;
  secure: number;
  vulnerable_percent: number;
  secure_percent: number;
  total: number;
}

export interface DashboardData {
  summary: DashboardSummary;
  os_categories: CategoryData;
  db_categories: CategoryData;
  unresolved_count: number;
  os_top_servers: TopServer[];
  db_top_servers: TopServer[];
  risk_distribution: RiskDistribution;
  vulnerability_ratio: VulnerabilityRatio;
}

/**
 * 대시보드 전체 데이터 조회
 */
export async function getDashboardData(): Promise<DashboardData> {
  const token = localStorage.getItem('access_token');

  const response = await axios.get(`${API_URL}/api/dashboard/data`, {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  return response.data;
}
