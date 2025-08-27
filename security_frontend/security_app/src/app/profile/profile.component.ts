import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClientModule } from '@angular/common/http';
import { TokenInfo } from '../model/tokenInfo';
import { TokenInfoService } from '../service/token-info.service';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatCardModule } from '@angular/material/card';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { Router, RouterModule } from '@angular/router';
import { MatToolbarModule } from '@angular/material/toolbar';
import { jwtDecode } from 'jwt-decode';
import { QRCodeModule } from 'angularx-qrcode'; 


@Component({
  selector: 'app-profile',
  standalone: true,
  imports: [
    CommonModule,
    HttpClientModule,
    FormsModule,
    ReactiveFormsModule,
    MatCardModule,
    MatButtonModule,
    MatFormFieldModule,
    MatInputModule,
    MatToolbarModule,
    RouterModule,
    QRCodeModule
  ],
  templateUrl: './profile.component.html',
  styleUrls: ['./profile.component.css']
})
export class ProfileComponent implements OnInit {
  tokens: TokenInfo[] = [];
  userSub: string = '';   // umesto email
  showSessions: boolean = false;
  currentJti: string = '';
  qrUrl: string = ''; 

  constructor(private tokenService: TokenInfoService, private router: Router) {}

  ngOnInit() {
    const token = localStorage.getItem('keycloakToken');
    if (token) {
      const decoded: any = jwtDecode(token);
      this.userSub = decoded.email; 
      localStorage.setItem('sub', this.userSub);
    }

    this.currentJti = localStorage.getItem('jti') || '';
    console.log("USER SUB:", this.userSub);

    this.loadTokens();
  }

  enable2FA() {
    this.tokenService.enable2FA(this.userSub).subscribe({
      next: (res: any) => {
        this.qrUrl = res.qrUrl;   // 👈 backend vraća QR kod
      },
          error: (err) => {
      console.error('Error enabling 2FA', err);
    }
    });
  }

  loadTokens() {
    this.tokenService.getActiveSessions().subscribe({
      next: data => {
        console.log("Current JTI:", this.currentJti);
        console.log("Tokens:", data);
        this.tokens = data;
      },
      error: err => console.error(err)
    });
  }

revoke(jti: string) {
  const email = this.userSub; // email, ne UUID
  console.log('Revoking token for email:', email, 'JTI:', jti);
  this.tokenService.revokeToken(jti, email).subscribe({
    next: () => {
      this.tokens = this.tokens.filter(t => t.jti !== jti);

      if (jti === this.currentJti) {
        this.logout();
      }
    },
    error: err => console.error('Revoke failed', err)
  });
}


  toggleSessions() {
    this.showSessions = !this.showSessions;
  }

  logout() {
    localStorage.clear();
    sessionStorage.clear();
    this.router.navigate(['/login']);
  }
}


