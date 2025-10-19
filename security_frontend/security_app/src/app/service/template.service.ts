import { HttpClient } from "@angular/common/http";
import { Injectable } from "@angular/core";
import { Observable } from "rxjs";
import { CertificateTemplateDTO } from "../model/certificateTemplateDto";

@Injectable({
  providedIn: 'root'
})
export class TemplateService {
  private apiUrl = 'http://localhost:8081/api/certificates';

  constructor(private http: HttpClient) {}

  createTemplate(dto: CertificateTemplateDTO): Observable<any> {
    const token = localStorage.getItem('keycloakToken');
    const headers = { 'Authorization': `Bearer ${token}` };

    return this.http.post<any>(`${this.apiUrl}`, dto, { headers });
  }

  getAllTemplates(): Observable<CertificateTemplateDTO[]> {
    const token = localStorage.getItem('keycloakToken');
    const headers = { 'Authorization': `Bearer ${token}` };

    return this.http.get<CertificateTemplateDTO[]>(`${this.apiUrl}`, { headers });
  }

  getTemplateById(id: number): Observable<CertificateTemplateDTO> {
    const token = localStorage.getItem('keycloakToken');
    const headers = { 'Authorization': `Bearer ${token}` };

    return this.http.get<CertificateTemplateDTO>(`${this.apiUrl}/${id}`, { headers });
  }

  getTemplatesByIssuer(issuerSerialNumber: string): Observable<CertificateTemplateDTO[]> {
    const token = localStorage.getItem('keycloakToken');
    const headers = { 'Authorization': `Bearer ${token}` };

    return this.http.get<CertificateTemplateDTO[]>(
      `${this.apiUrl}/by-issuer/${issuerSerialNumber}`,
      { headers }
    );
  }
}