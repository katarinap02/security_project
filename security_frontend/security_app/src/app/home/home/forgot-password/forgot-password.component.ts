import { Component } from '@angular/core';
import { FormBuilder, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { AuthService } from '../../../service/auth.service';
import Swal from 'sweetalert2';
import { MatButtonModule } from '@angular/material/button';
import { MatInputModule } from '@angular/material/input';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatCardModule } from '@angular/material/card';
import { CommonModule } from '@angular/common';
import { Router, RouterModule } from '@angular/router';

@Component({
  selector: 'app-forgot-password',
  standalone: true,
  imports: [MatButtonModule,
      MatInputModule,
      MatFormFieldModule,
      MatCardModule,
      ReactiveFormsModule,
      CommonModule,
      RouterModule],
  templateUrl: './forgot-password.component.html',
  styleUrl: './forgot-password.component.css'
})
export class ForgotPasswordComponent {
forgotForm: FormGroup;

  constructor(private fb: FormBuilder, private authService: AuthService,  private router: Router) {
    this.forgotForm = this.fb.group({
      email: ['', [Validators.required, Validators.email]]
    });
  }

onSubmit() {
  if (this.forgotForm.invalid) return;

  this.authService.forgotPassword(this.forgotForm.value.email).subscribe({
    next: (response) => {
      console.log('Success response:', response); // logujemo odgovor
      Swal.fire('Success', 'Password reset link sent to your email.', 'success');
    },
    error: (err) => {
      console.error('Error response:', err); // logujemo grešku
      if (err.error) console.error('Server message:', err.error);
      Swal.fire('Error', 'Failed to send reset link. Check console for details.', 'error');
    }
  });
}

}
