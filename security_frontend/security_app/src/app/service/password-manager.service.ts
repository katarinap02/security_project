import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface PasswordEntry {
  id?: number;
  ownerEmail: string;
  siteName: string;
  username: string;
  encryptedPassword: string;
}

@Injectable({
  providedIn: 'root'
})
export class PasswordManagerService {
  private baseUrl = 'http://localhost:8080/api/passwords';

  constructor(private http: HttpClient) {}

  getPasswords(email: string): Observable<PasswordEntry[]> {
    return this.http.get<PasswordEntry[]>(`${this.baseUrl}/${email}`);
  }

  addPassword(entry: PasswordEntry, publicKeyPem: string): Observable<PasswordEntry> {
    const body = { ...entry, publicKeyPem };
    return this.http.post<PasswordEntry>(`${this.baseUrl}/secure`, body);
  }
}
