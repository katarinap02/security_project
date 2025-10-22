import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';
import { PasswordShareDTO } from '../model/passwordShareDTO';
import { SharedPassword } from '../model/sharedPassword';

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
  private baseUrl = 'http://localhost:8081/api';

  constructor(private http: HttpClient) {}

  private getAuthHeaders(): HttpHeaders | undefined {
    const token = localStorage.getItem('keycloakToken');
    return token ? new HttpHeaders().set('Authorization', `Bearer ${token}`) : undefined;
  }

  getPasswords(): Observable<PasswordEntry[]> {
    const headers = this.getAuthHeaders();
    return this.http.get<PasswordEntry[]>(`${this.baseUrl}/passwords`, { headers });
  }

  addPassword(dto: PasswordEntry): Observable<PasswordEntry> {
    const headers = this.getAuthHeaders();
    return this.http.post<PasswordEntry>(`${this.baseUrl}/passwords`, dto, { headers });
  }

  deletePassword(id: number): Observable<void> {
    const headers = this.getAuthHeaders();
    return this.http.delete<void>(`${this.baseUrl}/passwords/${id}`, { headers });
  }
  

  getSharedPasswords(): Observable<SharedPassword[]> {
    const headers = this.getAuthHeaders();
    return this.http.get<SharedPassword[]>(`${this.baseUrl}/passwords/shares`, { headers });
  }

  getUsers(): Observable<{ id: number, email: string }[]> {
    const headers = this.getAuthHeaders();
    if (!headers) {
      throw new Error('JWT token missing! User probably not logged in.');
    }
    return this.http.get<{ id: number, email: string }[]>(`${this.baseUrl}/passwords/shares/end-entities`, { headers });
  }

  sharePassword(dto: PasswordShareDTO): Observable<SharedPassword> {
    const headers = this.getAuthHeaders();
    return this.http.post<SharedPassword>(`${this.baseUrl}/passwords/shares`, dto, { headers });
  }

}
