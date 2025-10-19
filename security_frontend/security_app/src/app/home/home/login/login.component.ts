import { CommonModule } from '@angular/common';
import { Component, ElementRef, AfterViewInit, ViewChild } from '@angular/core';
import { FormBuilder, FormGroup, FormsModule, ReactiveFormsModule, Validators } from '@angular/forms';
import { MatCardModule } from '@angular/material/card';
import { MatButtonModule } from '@angular/material/button';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { AuthService } from '../../../service/auth.service';
import { Router } from '@angular/router';
import Swal from 'sweetalert2';
import { RouterModule } from '@angular/router';
import { jwtDecode } from "jwt-decode";
import { TwoFactorService } from '../../../service/two-factor.service';


declare var grecaptcha: any;

interface DecodedToken {
  jti: string;
  sub: string; // email
  exp: number;
  
}

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    ReactiveFormsModule,
    MatCardModule,
    MatButtonModule,
    MatFormFieldModule,
    MatInputModule,
    RouterModule,
    ReactiveFormsModule
  ],
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css']
})
export class LoginComponent implements AfterViewInit {
  loginForm!: FormGroup;
  siteKey: string = '6Lft_qkrAAAAAOh8Jd4JrICGZ_wkVpEvsJyQl0zp'; 
  captchaWidgetId: any = null;
  showTwoFactor: boolean = false;


  @ViewChild('captchaElem', { static: true }) captchaElem!: ElementRef;

  constructor(private fb: FormBuilder, private authService: AuthService, private router: Router, private twoFactorService: TwoFactorService ) {
    this.loginForm = this.fb.group({
      email: ['', [Validators.required, Validators.email]],
      password: ['', Validators.required],
      twoFactorCode: ['']
    });
      this.twoFactorService.showTwoFactor$.subscribe(value => {
      this.showTwoFactor = value;
    });
  }

  ngAfterViewInit(): void {
    // Render reCAPTCHA kada se komponenta inicijalizuje
    this.captchaWidgetId = grecaptcha.render(this.captchaElem.nativeElement, {
      sitekey: this.siteKey
    });
  }
onSubmit() {
  const captchaToken = grecaptcha.getResponse(this.captchaWidgetId);

  if (this.loginForm.invalid || !captchaToken) {
    Swal.fire({
      icon: 'warning',
      title: this.loginForm.invalid ? 'Invalid input' : 'CAPTCHA required',
      text: this.loginForm.invalid ? 'Please fill in all fields correctly.' : 'Please solve the CAPTCHA before submitting.'
    });
    grecaptcha.reset(this.captchaWidgetId);
    return;
  }

  const email = this.loginForm.value.email;
  const password = this.loginForm.value.password;
  const twoFactorCode = this.loginForm.value.twoFactorCode;

  // Pošalji login request
  this.authService.login({ email, password, recaptchaToken: captchaToken, twoFactorCode }).subscribe({
    next: (res: any) => {
      if (res.twoFactorRequired) {
        // Backend traži 2FA, prikazi input za kod
        this.showTwoFactor = true;
        this.twoFactorService.setShowTwoFactor(true);

        Swal.fire({
          icon: 'info',
          title: 'Two-Factor Authentication required',
          text: 'Please enter your 2FA code.'
        });
        grecaptcha.reset(this.captchaWidgetId);
      } else {
        // Login uspešan, sa tokenom
        const decoded: DecodedToken = jwtDecode(res.token);
        console.log('Decoded token:', decoded); 
        localStorage.setItem('keycloakToken', res.token);
        localStorage.setItem('email', decoded.sub);
        localStorage.setItem('jti', decoded.jti);
        Swal.fire({
          icon: 'success',
          title: 'Login successful'
        });
        this.router.navigate(['/profile']);
      }
    },
    error: (err: any) => {
      Swal.fire({
        icon: 'error',
        title: 'Login failed',
        text: err.error?.message || 'An error occurred during login.'
      });
      grecaptcha.reset(this.captchaWidgetId);
    }
  });
}



sendLogin(captchaToken: string) {
    const loginData = {
        email: this.loginForm.value.email,
        password: this.loginForm.value.password,
        recaptchaToken: captchaToken,
        twoFactorCode: this.loginForm.value.twoFactorCode || null
    };

    this.authService.login(loginData).subscribe({
        next: (res: any) => {
            Swal.fire({
                icon: 'success',
                title: 'Login successful'
            });
            const decoded: DecodedToken = jwtDecode(res.token);
            localStorage.setItem('email', decoded.sub);
            localStorage.setItem('jti', res.jti);
            localStorage.setItem('keycloakToken', res.token);
            this.router.navigate(['/profile']);
        },
        error: (err: any) => {
            Swal.fire({
                icon: 'error',
                title: 'Login failed',
                text: err.error?.message || 'An error occurred during login.'
            });
            grecaptcha.reset(this.captchaWidgetId);
        }
    });
}


}


