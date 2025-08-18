import { CommonModule } from '@angular/common';
import { Component, ElementRef, AfterViewInit, ViewChild } from '@angular/core';
import { FormBuilder, FormGroup, FormsModule, ReactiveFormsModule, Validators } from '@angular/forms';
import { MatCardModule } from '@angular/material/card';
import { MatButtonModule } from '@angular/material/button';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { AuthService } from '../../../service/auth.service';
import { Router } from '@angular/router';

// Skripta se učitava globalno u index.html
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
  siteKey: string = '6Lft_qkrAAAAAOh8Jd4JrICGZ_wkVpEvsJyQl0zp'; // zameni sa svojim site key
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
      alert('Popunite sve ispravno!');
      grecaptcha.reset(this.captchaWidgetId);
      return;
    }

    if (!token) {
      alert('Molimo vas, rešite CAPTCHA!');
      return;
    }

    const loginData = {
      email: this.loginForm.value.email,
      password: this.loginForm.value.password,
      recaptchaToken: token
    };

    this.authService.login(loginData).subscribe({
      next: (res: any) => {
        alert('Uspešna prijava!');
        grecaptcha.reset(this.captchaWidgetId); // resetuje captcha nakon uspešne prijave
        this.router.navigate(['/profile']); // preusmerava na profile
      },
      error: (err: any) => {
        alert('Greška prilikom prijave: ' + (err.error?.message || err.message));
        grecaptcha.reset(this.captchaWidgetId); // resetuje captcha nakon greške
      }
    });
  }
}
