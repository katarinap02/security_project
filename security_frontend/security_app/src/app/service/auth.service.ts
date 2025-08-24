import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, tap } from 'rxjs'; 
import { UserDTO } from '../model/user';

interface LoginResponse {
  token: string;
  type: string;
} 

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private apiUrl = 'http://localhost:8080/api/users'; 

  constructor(private http: HttpClient) { }

  register(user: UserDTO): Observable<any> {
    return this.http.post(`${this.apiUrl}/register`, user);
  }
  
  login(loginData: any): Observable<LoginResponse> {
    return this.http.post<LoginResponse>(`${this.apiUrl}/login`, loginData).pipe(
      tap(res => {
        localStorage.setItem('jwtToken', res.token); // čuvamo JWT token
        localStorage.setItem('email', loginData.email);
      })
    );
  }

  getToken(): string | null {
    return localStorage.getItem('jwtToken');
    
  }

  logout() {
    localStorage.removeItem('jwtToken');
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

  getRoleIdsByEmail(email: string): Observable<number[]> {
    return this.http.get<number[]>(`${this.apiUrl}/roles/ids/${email}`);
  }

}
