import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { IssueCertificateDTO } from '../model/issuerCertificateDto';
import { Certificate } from '../model/certificate';
import { jwtDecode } from 'jwt-decode';

@Injectable({
  providedIn: 'root'
})
export class CertificateService {
  private apiUrl = 'http://localhost:8081/api/certificates';

  constructor(private http: HttpClient) { }

  issueCertificate(dto: IssueCertificateDTO): Observable<Certificate> {
  const token = localStorage.getItem('keycloakToken');
  let email = '';
  if (token) {
    const decoded: any = jwtDecode(token);
    email = decoded.preferred_username; // ili decoded.preferred_username
  }

  // Pošalji DTO + email u body
  return this.http.post<Certificate>(`${this.apiUrl}/issue`, { dto, email });
}

}