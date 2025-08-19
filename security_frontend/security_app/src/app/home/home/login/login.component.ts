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


declare var grecaptcha: any;

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
    MatInputModule
  ],
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css']
})
export class LoginComponent implements AfterViewInit {
  loginForm!: FormGroup;
  siteKey: string = '6Lft_qkrAAAAAOh8Jd4JrICGZ_wkVpEvsJyQl0zp'; 
  captchaWidgetId: any = null;

  @ViewChild('captchaElem', { static: true }) captchaElem!: ElementRef;

  constructor(private fb: FormBuilder, private authService: AuthService, private router: Router) {
    this.loginForm = this.fb.group({
      email: ['', [Validators.required, Validators.email]],
      password: ['', Validators.required]
    });
  }

  ngAfterViewInit(): void {
    // Render reCAPTCHA kada se komponenta inicijalizuje
    this.captchaWidgetId = grecaptcha.render(this.captchaElem.nativeElement, {
      sitekey: this.siteKey
    });
  }

  onSubmit() {
    const token = grecaptcha.getResponse(this.captchaWidgetId);

    if (this.loginForm.invalid) {
          Swal.fire({
      icon: 'warning',
      title: 'Invalid input',
      text: 'Please fill in all fields correctly.'
    });
      grecaptcha.reset(this.captchaWidgetId);
      return;
    }

    if (!token) {
          Swal.fire({
      icon: 'warning',
      title: 'CAPTCHA required',
      text: 'Please solve the CAPTCHA before submitting.'
    });
      return;
    }

    const loginData = {
      email: this.loginForm.value.email,
      password: this.loginForm.value.password,
      recaptchaToken: token
    };

    this.authService.login(loginData).subscribe({
      next: (res: any) => {
              Swal.fire({
        icon: 'success',
        title: 'Login successful',
        text: 'You have been logged in successfully.'
      });
        grecaptcha.reset(this.captchaWidgetId); // resetuje captcha nakon uspešne prijave
        this.router.navigate(['/profile']); // preusmerava na profile
      },
      error: (err: any) => {
              Swal.fire({
        icon: 'error',
        title: 'Login failed',
        text: err.error?.message || 'An error occurred during login.'
      });
        grecaptcha.reset(this.captchaWidgetId); // resetuje captcha nakon greške
      }
    });
  }
}
