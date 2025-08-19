import { Component } from '@angular/core';
import { FormBuilder, FormGroup, FormsModule, ReactiveFormsModule, Validators } from '@angular/forms';
import zxcvbn from 'zxcvbn';
import { MatCardModule } from '@angular/material/card';
import { MatButtonModule } from '@angular/material/button';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { CommonModule } from '@angular/common';
import { AuthService } from '../../../service/auth.service';
import { Router } from '@angular/router';
import Swal from 'sweetalert2';


@Component({
  selector: 'app-registration',
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
  templateUrl: './registration.component.html',
  styleUrl: './registration.component.css'
})

export class RegistrationComponent {
  registerForm: FormGroup;
  passwordStrength: number = 0;
  passwordStrengthPercent: string = '0%';
  passwordStrengthColor: string = '#ccc';
  passwordStrengthLabel: string = '';

  constructor(private fb: FormBuilder, private authService: AuthService, private router: Router) {
    this.registerForm = this.fb.group({
      email: ['', [Validators.required, Validators.email]],
      password: ['', [Validators.required, Validators.minLength(8),  Validators.maxLength(64)]],
      confirmPassword: ['', Validators.required],
      name: ['', Validators.required],
      surname: ['', Validators.required],
      organization: ['', Validators.required]
    });

  }

  // onPasswordInput() {
  //   const val = this.registerForm.get('password')?.value;
  //   this.passwordStrength = val ? zxcvbn(val).score : 0;
  // }
onPasswordInput() {
  const val = this.registerForm.get('password')?.value;
  const score = val ? zxcvbn(val).score : 0;

  this.passwordStrength = score;

  // Boja i labela
  switch(score) {
    case 0:
      this.passwordStrengthColor = '#ff4d4d'; // crvena
      this.passwordStrengthLabel = 'Very Weak';
      break;
    case 1:
      this.passwordStrengthColor = '#ff944d'; // narandžasta
      this.passwordStrengthLabel = 'Weak';
      break;
    case 2:
      this.passwordStrengthColor = '#ffdb4d'; // žuta
      this.passwordStrengthLabel = 'Medium';
      break;
    case 3:
      this.passwordStrengthColor = '#a6e22e'; // svetlo zelena
      this.passwordStrengthLabel = 'Strong';
      break;
    case 4:
      this.passwordStrengthColor = '#00b300'; // tamno zelena
      this.passwordStrengthLabel = 'Very Strong';
      break;
  }

  // Width za progress bar
  this.passwordStrengthPercent = ((score + 1) / 5 * 100) + '%';
}

  passwordsMatch(): boolean {
    return this.registerForm.get('password')?.value === this.registerForm.get('confirmPassword')?.value;
  }

submit() {
  if (this.registerForm.invalid || !this.passwordsMatch()) {
        Swal.fire({
      icon: 'warning',
      title: 'Invalid input',
      text: 'Please fill in all fields correctly and ensure passwords match.'
    });

    return;
  }
    if (this.passwordStrength <= 1) {
      Swal.fire({
        icon: 'warning',
        title: 'Weak password',
        text: 'Please choose a stronger password.'
      });
      return;
    }
  // Kreiraj UserDTO objekat
  const user = {
    email: this.registerForm.get('email')?.value,
    password: this.registerForm.get('password')?.value,
    confirmPassword: this.registerForm.get('confirmPassword')?.value,
    name: this.registerForm.get('name')?.value,
    surname: this.registerForm.get('surname')?.value,
    organization: this.registerForm.get('organization')?.value
  };

  // Pozovi AuthService za registraciju
  this.authService.register(user).subscribe({
    next: (res) => {
            Swal.fire({
        icon: 'success', title: 'Registration successful', text: 'Activation email has been sent.'});
      this.registerForm.reset();
      this.router.navigate(['/login']);
    },
    error: (err) => {
            Swal.fire({
        icon: 'error', title: 'Registration failed', text: err.error?.message || 'An error occurred during registration.'});

    }
  });
}

}
