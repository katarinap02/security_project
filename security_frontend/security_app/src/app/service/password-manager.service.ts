import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { from, mergeMap, Observable } from 'rxjs';

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

  // addPassword(entry: PasswordEntry, publicKeyPem: string): Observable<PasswordEntry> {
  //   const body = { ...entry, publicKeyPem };
  //   return this.http.post<PasswordEntry>(`${this.baseUrl}/secure`, body);
  // }

  addPassword(entry: PasswordEntry, publicKeyPem: string): Observable<PasswordEntry> {
  const encoder = new TextEncoder();
  const data = encoder.encode(entry.encryptedPassword); // plaintext password

  // Koristimo from() da pretvorimo Promise u Observable
  return from(
    window.crypto.subtle.importKey(
      'spki',
      this.pemToArrayBuffer(publicKeyPem),
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['encrypt']
    ).then(publicKey =>
      window.crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, data)
    ).then(encrypted => {
      const base64 = btoa(String.fromCharCode(...new Uint8Array(encrypted)));
      entry.encryptedPassword = base64; // zamenjujemo plaintext sa šifrom
      return entry;
    })
  ).pipe(
    mergeMap(e => this.http.post<PasswordEntry>(`${this.baseUrl}`, e))
  );
}


// Helper za PEM -> ArrayBuffer
private pemToArrayBuffer(pem: string): ArrayBuffer {
  const b64 = pem.replace(/-----.*?-----/g, '').replace(/\s+/g, '');
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

}
