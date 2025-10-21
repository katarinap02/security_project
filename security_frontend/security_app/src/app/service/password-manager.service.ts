import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface PasswordEntry {
  id?: number;
  siteName: string;
  username: string;
  encryptedPassword: string;
  encryptedAesKey: string;
  iv: string;
}

@Injectable({
  providedIn: 'root'
})
export class PasswordManagerService {
  private baseUrl = 'http://localhost:8081/api/passwords';

  constructor(private http: HttpClient) {}

  private getAuthHeaders(): HttpHeaders | undefined {
    const token = localStorage.getItem('keycloakToken');
    return token ? new HttpHeaders().set('Authorization', `Bearer ${token}`) : undefined;
  }

  getPasswords(): Observable<PasswordEntry[]> {
    const headers = this.getAuthHeaders();
    return this.http.get<PasswordEntry[]>(this.baseUrl, { headers });
  }

  addPassword(dto: PasswordEntry): Observable<PasswordEntry> {
    const headers = this.getAuthHeaders();
    return this.http.post<PasswordEntry>(this.baseUrl, dto, { headers });
  }

  deletePassword(id: number): Observable<void> {
    const headers = this.getAuthHeaders();
    return this.http.delete<void>(`${this.baseUrl}/${id}`, { headers });
  }
}
