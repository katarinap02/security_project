import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { TokenInfo } from '../model/tokenInfo';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class TokenInfoService {

  private baseUrl = 'http://localhost:8081/api/users';

  constructor(private http: HttpClient) { }
  
  revokeToken(jti: string, sub: string): Observable<any> {
    const token = localStorage.getItem('keycloakToken');
    console.log('Revoking token JTI:', jti, 'for sub:', sub, 'Using JWT:', token);

    const headers = { 'Authorization': `Bearer ${token}` };

    return this.http.post(`${this.baseUrl}/sessions/revoke?jti=${jti}&sub=${sub}`, {}, { headers });
  }


getActiveSessions(): Observable<TokenInfo[]> {
  const token = localStorage.getItem('keycloakToken');
 
 console.log('Fetching active sessions with JWT:', token);

  const headers = { 'Authorization': `Bearer ${token}` };

  return this.http.get<TokenInfo[]>(`${this.baseUrl}/sessions`, { headers });
}

enable2FA(sub: string) {
  return this.http.post<{ qrUrl: string }>(`http://localhost:8081/api/users/enable-2fa`, { sub });
}

}
