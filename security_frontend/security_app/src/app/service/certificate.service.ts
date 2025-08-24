import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { IssueCertificateDTO } from '../model/issuerCertificateDto';
import { Certificate } from '../model/certificate';

@Injectable({
  providedIn: 'root'
})
export class CertificateService {
  private apiUrl = 'http://localhost:8080/api/certificates';

  constructor(private http: HttpClient) { }

  issueCertificate(dto: IssueCertificateDTO): Observable<Certificate> {
    return this.http.post<Certificate>(`${this.apiUrl}/issue`, dto);
  }
}