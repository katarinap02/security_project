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

  constructor(private fb: FormBuilder, private authService: AuthService, private router: Router) {
    this.registerForm = this.fb.group({
      email: ['', [Validators.required, Validators.email]],
      password: ['', [Validators.required, Validators.minLength(8)]],
      confirmPassword: ['', Validators.required],
      name: ['', Validators.required],
      surname: ['', Validators.required],
      organization: ['', Validators.required]
    });

  }

  onPasswordInput() {
    const val = this.registerForm.get('password')?.value;
    this.passwordStrength = val ? zxcvbn(val).score : 0;
  }


  passwordsMatch(): boolean {
    return this.registerForm.get('password')?.value === this.registerForm.get('confirmPassword')?.value;
  }

submit() {
  if (this.registerForm.invalid || !this.passwordsMatch()) {
    alert('Popunite sve ispravno!');

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
      alert('Uspešna registracija! Aktivacioni mejl je poslat.');
      this.registerForm.reset();
      this.router.navigate(['/login']);
    },
    error: (err) => {
      alert('Greška prilikom registracije: ' + (err.error?.message || err.message));

    }
  });
}

}
