import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import { jwtDecode } from 'jwt-decode';
import { CSRDTO } from '../model/csr';
import { CA } from '../model/ca';
import { Certificate } from '../model/certificate';
import { SignCSRRequest } from '../model/signCsr';

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

  /**
   * Vraća sve CSR-ove trenutno ulogovanog korisnika
   * @returns Observable sa listom CSRDTO objekata
   */
  getUserCSRs(): Observable<CSRDTO[]> {
    const token = localStorage.getItem('keycloakToken');
    const headers = token ? new HttpHeaders().set('Authorization', `Bearer ${token}`) : undefined;
    return this.http.get<CSRDTO[]>(`${this.apiUrl}/my`, { headers });
  }

  getAllCAs() {
    const token = localStorage.getItem('keycloakToken');
    const headers = token ? new HttpHeaders().set('Authorization', `Bearer ${token}`) : undefined;
    return this.http.get<CA[]>(`http://localhost:8081/api/ca`, { headers });
  }

}
