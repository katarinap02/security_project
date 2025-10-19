import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';
import { jwtDecode } from 'jwt-decode';
import { CSRDTO } from '../model/csr';

@Injectable({
  providedIn: 'root'
})
export class CsrService {
  private apiUrl = 'http://localhost:8081/api/csr';

  constructor(private http: HttpClient) { }

  /**
   * Upload-uje CSR fajl na backend
   * @param file File koji se upload-uje
   * @returns Observable sa eventualnim odgovorom (CSRDTO)
   */
  uploadCSR(file: File): Observable<CSRDTO> {
    const token = localStorage.getItem('keycloakToken');
    let email = '';
    if (token) {
      const decoded: any = jwtDecode(token);
      email = decoded.preferred_username;
    }

    // HttpHeaders objekat
    const headers = { 'Authorization': `Bearer ${token}` };
    
    // FormData za slanje fajla
    const formData = new FormData();
    formData.append('file', file);

    // Slanje POST zahteva sa formData i headers
    return this.http.post<CSRDTO>(`${this.apiUrl}/upload`, formData, { headers });
  }

  // Ako bude trebalo, možeš dodati još GET metode, npr.:
  getUserCSRs(): Observable<CSRDTO[]> {
    const token = localStorage.getItem('keycloakToken');
    const headers = token ? new HttpHeaders().set('Authorization', `Bearer ${token}`) : undefined;
    return this.http.get<CSRDTO[]>(`${this.apiUrl}/user`, { headers });
  }
}
