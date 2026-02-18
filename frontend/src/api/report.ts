/**
 * 보고서 생성/다운로드 API
 */

import axios from 'axios';

const API_URL = `http://${window.location.hostname}:8000`;

/**
 * 취약점 진단 결과 엑셀 보고서 생성 및 다운로드
 */
export async function downloadReport(): Promise<void> {
  const token = localStorage.getItem('access_token');

  const response = await axios.post(
    `${API_URL}/api/reports/generate`,
    {},
    {
      headers: {
        Authorization: `Bearer ${token}`,
      },
      responseType: 'blob',
    },
  );

  // Content-Disposition 헤더에서 파일명 추출
  const disposition = response.headers['content-disposition'] || '';
  let filename = '취약점진단결과.xlsx';

  const utf8Match = disposition.match(/filename\*=UTF-8''(.+)/);
  if (utf8Match) {
    filename = decodeURIComponent(utf8Match[1]);
  }

  // Blob → 다운로드
  const blob = new Blob([response.data], {
    type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  });
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  window.URL.revokeObjectURL(url);
  document.body.removeChild(a);
}
