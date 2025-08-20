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

@Component({
  selector: 'app-profile',
  standalone: true,
  imports: [CommonModule, 
    HttpClientModule,
      CommonModule,
      FormsModule,
      ReactiveFormsModule,
      MatCardModule,
      MatButtonModule,
      MatFormFieldModule,
      MatInputModule,
      MatToolbarModule,
      RouterModule],
  templateUrl: './profile.component.html',
  styleUrls: ['./profile.component.css']
})
export class ProfileComponent implements OnInit {
  tokens: TokenInfo[] = [];
  userEmail: string = ''; // postavi email trenutno ulogovanog korisnika
  showSessions: boolean = false;
  currentJti: string = '';
  constructor(private tokenService: TokenInfoService, private router: Router) {}

  ngOnInit() {
    this.userEmail = localStorage.getItem('email') || ''; // ili uzmi iz AuthService
    this.currentJti = localStorage.getItem('jti') || ''; 
    this.loadTokens();
  }

loadTokens() {
  this.tokenService.getActiveSessions(this.userEmail).subscribe({
    next: data => {
      // console.log("Current JTI:", this.currentJti);
      // console.log("Tokens:", data);
      this.tokens = data;
    },
    error: err => console.error(err)
  });
}


revoke(jti: string) {
  this.tokenService.revokeToken(jti, this.userEmail).subscribe(() => {
    this.tokens = this.tokens.filter(t => t.jti !== jti);

    if (jti === this.currentJti) {
      // Ako je opozvana trenutna sesija, logout
      this.logout();
    }
  });
}

  toggleSessions() {
  this.showSessions = !this.showSessions;
}

  logout() {
  // obriši sve iz localStorage ili sessionStorage
  localStorage.clear();
  sessionStorage.clear();

  // prebaci na login rutu
  this.router.navigate(['/login']);

}
}