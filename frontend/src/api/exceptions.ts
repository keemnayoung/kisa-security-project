/**
 * 예외 처리 API 클라이언트
 */

import axios from 'axios';

const API_URL = `http://${window.location.hostname}:8000`;

export interface ExceptionItem {
  exception_id: number;
  server_id: string;
  hostname: string;
  ip_address: string;
  item_code: string;
  item_title: string;
  severity: string;
  reason: string;
  valid_date: string;
  is_active: boolean;
}

export interface ExceptionListResponse {
  total: number;
  active_count: number;
  expired_count: number;
  items: ExceptionItem[];
}

export interface ExceptionCreateRequest {
  server_id: string;
  item_code: string;
  reason: string;
  valid_date: string;
}

export interface ExceptionBulkCreateRequest {
  item_code: string;
  reason: string;
  valid_date: string;
  server_ids?: string[];
}

export async function getExceptions(): Promise<ExceptionListResponse> {
  const token = localStorage.getItem('access_token');
  const response = await axios.get(`${API_URL}/api/exceptions`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  return response.data;
}

export async function createException(data: ExceptionCreateRequest) {
  const token = localStorage.getItem('access_token');
  const response = await axios.post(`${API_URL}/api/exceptions`, data, {
    headers: { Authorization: `Bearer ${token}` },
  });
  return response.data;
}

export async function createBulkException(data: ExceptionBulkCreateRequest) {
  const token = localStorage.getItem('access_token');
  const response = await axios.post(`${API_URL}/api/exceptions/bulk`, data, {
    headers: { Authorization: `Bearer ${token}` },
  });
  return response.data;
}

export async function deleteException(exceptionId: number) {
  const token = localStorage.getItem('access_token');
  const response = await axios.delete(`${API_URL}/api/exceptions/${exceptionId}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  return response.data;
}
