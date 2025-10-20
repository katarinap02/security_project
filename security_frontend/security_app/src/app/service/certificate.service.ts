import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { IssueCertificateDTO } from '../model/issuerCertificateDto';
import { CertificateDTO } from '../model/certificateDto';
import { Certificate } from '../model/certificate';
import { jwtDecode } from 'jwt-decode';
import { RevokeCertificateDTO } from '../model/revokDto';

@Injectable({
  providedIn: 'root'
})
export class CertificateService {
  private apiUrl = 'http://localhost:8081/api/certificates';

  constructor(private http: HttpClient) { }

  issueCertificate(dto: IssueCertificateDTO): Observable<Certificate> {
  const token = localStorage.getItem('keycloakToken');
  const headers = { 'Authorization': `Bearer ${token}` };
    console.log(token)
  return this.http.post<Certificate>(`${this.apiUrl}/issue`, dto, { headers });
}


getCertificatesForUser(): Observable<CertificateDTO[]> {
  const token = localStorage.getItem('keycloakToken');
  let email = '';
  if (token) {
    const decoded: any = jwtDecode(token);
    email = decoded.preferred_username; 
  }

  const headers = { 'Authorization': `Bearer ${token}` };

  return this.http.get<CertificateDTO[]>(`${this.apiUrl}/user`, { headers });
}

downloadCertificate(serialNumber: string): Observable<Blob> {
  const token = localStorage.getItem('keycloakToken');
  let email = '';
  if (token) {
    const decoded: any = jwtDecode(token);
    email = decoded.preferred_username; 
  }

  const headers = { 'Authorization': `Bearer ${token}` };

  return this.http.get(`${this.apiUrl}/download/${serialNumber}`, { 
    headers, 
    responseType: 'blob' // 👈 bitno! preuzimamo binarni fajl
  });
}

revokeCertificate(dto: RevokeCertificateDTO): Observable<any> {
  const token = localStorage.getItem('keycloakToken');
  const headers = { 'Authorization': `Bearer ${token}` };

    return this.http.post(`${this.apiUrl}/revoke`, dto, { headers });
  }



}