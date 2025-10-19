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
import Swal from 'sweetalert2';
import { AuthService } from '../service/auth.service';
import { TwoFactorService } from '../service/two-factor.service';


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



  isAdmin: boolean = false;
  isCaUser: boolean = false;
  showCARegistration: boolean = false;
  caEmail: string = '';
  caName: string = '';
  caSurname: string = '';
  caOrganization: string = '';


  constructor(private tokenService: TokenInfoService, private router: Router, private authService: AuthService, private twoFactorService: TwoFactorService) {}

  activeTab: 'sessions' | 'twoFactor' | null = null; 

  toggleSessions() {
    this.activeTab = this.activeTab === 'sessions' ? null : 'sessions';
    this.showSessions = !this.showSessions;
  }

  toggleTwoFactor() {
    this.activeTab = this.activeTab === 'twoFactor' ? null : 'twoFactor';
  }

  ngOnInit() {
    const token = localStorage.getItem('keycloakToken');
    if (token) {
      const decoded: any = jwtDecode(token);
      this.userSub = decoded.email; 
      localStorage.setItem('sub', this.userSub);
      
      this.isAdmin = decoded.resource_access?.['my-app']?.roles?.includes('ROLE_ADMIN') || false;
      this.isCaUser = decoded.resource_access?.['my-app']?.roles?.includes('ROLE_CA_USER') || false;
      console.log('ROLEE:', this.isCaUser);
    }

    //this.currentJti = localStorage.getItem('jti') || '';


    console.log("USER SUB:", this.userSub);

    this.loadTokens();
  }

  openCARegistration() {
  this.showCARegistration = true;
}

closeCARegistration() {
  this.showCARegistration = false;
}


  enable2FA() {
    this.tokenService.enable2FA(this.userSub).subscribe({
      next: (res: any) => {
        console.log('QR URL from backend:', res.qrUrl);
        this.qrUrl = res.qrUrl;   // backend vraća QR kod
              // aktiviraj showTwoFactor u LoginComponent
      this.twoFactorService.setShowTwoFactor(true);
      },
          error: (err) => {
      console.error('Error enabling 2FA', err);
    }
    });
  }


  loadTokens() {
  this.tokenService.getActiveSessions().subscribe({
    next: data => {
      
      console.log("LocalStorage JTI:", localStorage.getItem('jti'));
      console.log("Tokens:", data);
      this.tokens = data;

      // Nađi token sa najnovijim lastActivity
      const latestToken = this.tokens
        .sort((a, b) => new Date(b.lastActivity).getTime() - new Date(a.lastActivity).getTime())[0];

      this.currentJti = latestToken?.jti || '';
      
      console.log("Updated current JTI:", this.currentJti);
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




  logout() {
    localStorage.clear();
    sessionStorage.clear();
    this.router.navigate(['/login']);
  }


  submitCARegistration(form: any) {
  if (form.invalid) {
    Swal.fire({
      icon: 'warning',
      title: 'Invalid input',
      text: 'Please fill in all fields correctly.'
    });
    return;
  }

  const user = {
    email: this.caEmail,
    name: this.caName,
    surname: this.caSurname,
    organization: this.caOrganization
  };

  // Pozovi backend endpoint za registraciju CA korisnika
  this.authService.registerCAUser(user).subscribe({  
    next: () => {
      Swal.fire({
        icon: 'success',
        title: 'CA User registered',
        text: 'Temporary password has been sent to the user.'
      });

      // Reset forme
      this.caEmail = '';
      this.caName = '';
      this.caSurname = '';
      this.caOrganization = '';
      this.showCARegistration = false;
    },
    error: err => {
      Swal.fire({
        icon: 'error',
        title: 'Registration failed',
        text: err.error?.message || 'An error occurred.'
      });
    }
  });
}

}


