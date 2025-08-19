import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { TokenInfo } from '../model/tokenInfo';
import { Observable } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class TokenInfoService {

  private baseUrl = 'http://localhost:8080/api/users';

  constructor(private http: HttpClient) { }

  // getActiveSessions(email: string): Observable<TokenInfo[]> {
  //   return this.http.get<TokenInfo[]>(`${this.baseUrl}/sessions?email=${email}`);
  // }

  // revokeToken(jti: string, email: string): Observable<any> {
  //   return this.http.post(`${this.baseUrl}/sessions/revoke?jti=${jti}&email=${email}`, {});
  // }
  
revokeToken(jti: string, email: string): Observable<any> {
  const token = localStorage.getItem('jwtToken'); // uzmi token iz localStorage
  const headers = { 'Authorization': `Bearer ${token}` };

  return this.http.post(`${this.baseUrl}/sessions/revoke?jti=${jti}&email=${email}`, {}, { headers });
}

getActiveSessions(email: string): Observable<TokenInfo[]> {
  const token = localStorage.getItem('jwtToken');
  const headers = { 'Authorization': `Bearer ${token}` };

  return this.http.get<TokenInfo[]>(`${this.baseUrl}/sessions?email=${email}`, { headers });
}


}
