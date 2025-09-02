import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { map, Observable, tap, catchError, of } from 'rxjs'; 
import { UserDTO } from '../model/user';

// interface LoginResponse {
//   token: string;
//   type: string;
//   accessToken: string;
// } 
interface LoginResponse {
  token: string;
  expiresIn: number;
  jti: string;
}
@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private apiUrl = 'http://localhost:8081/api/users'; 

  constructor(private http: HttpClient) { }

  register(user: UserDTO): Observable<any> {
    return this.http.post(`${this.apiUrl}/register`, user);
  }

registerCAUser(user: { email: string; name: string; surname: string; organization: string }) {
  const token = localStorage.getItem('keycloakToken');
  console.log('Fetching active sessions with JWT registracijaa CA:', token);

  const headers = { Authorization: `Bearer ${token}` };

  return this.http.post(`${this.apiUrl}/register-ca`, user, { headers });
}

  login(loginData: any): Observable<LoginResponse> {
    return this.http.post<LoginResponse>(`${this.apiUrl}/login`, loginData).pipe(
      tap(res => {
        localStorage.setItem('keycloakToken', res.token); // čuvamo JWT token
        localStorage.setItem('email', loginData.email);
        

      })
    );
  }

  getToken(): string | null {
    return localStorage.getItem('keycloakToken');
  }

  logout() {
    localStorage.removeItem('keycloakToken');
  }

  isLoggedIn(): boolean {
    return !!this.getToken();
  }

  forgotPassword(email: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/forgot-password`, { email });
  }

  resetPassword(token: string, password: string) {
    return this.http.post(`${this.apiUrl}/reset-password`, { token, password });
  }

  checkTwoFactor(email: string, twoFactorCode: string | number): Observable<boolean> {
    return this.http.post<{ success: boolean }>(`${this.apiUrl}/check-2fa`, { email, twoFactorCode })
      .pipe(
        map(res => res.success),
        catchError(err => {
          console.error('2FA verification failed', err);
          return of(false);
        })
      );
  }

}
