import { Component } from '@angular/core';
import { FormBuilder, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { ActivatedRoute, Router, RouterModule } from '@angular/router';
import Swal from 'sweetalert2';
import { AuthService } from '../../../service/auth.service';
import { MatButtonModule } from '@angular/material/button';
import { MatInputModule } from '@angular/material/input';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatCardModule } from '@angular/material/card';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-reset-password',
  standalone: true,
  imports: [MatButtonModule,
    MatInputModule,
    MatFormFieldModule,
    MatCardModule,
    ReactiveFormsModule,
    CommonModule,
    RouterModule
  ],
  templateUrl: './reset-password.component.html',
  styleUrl: './reset-password.component.css'
})
export class ResetPasswordComponent {
 resetForm: FormGroup;
  token: string | null;

  constructor(private fb: FormBuilder, private route: ActivatedRoute, private authService: AuthService,  private router: Router) {
    this.resetForm = this.fb.group({
      password: ['', [Validators.required, Validators.minLength(8)]]
    });
    this.token = this.route.snapshot.queryParamMap.get('token');
  }

onSubmit() {
  if (this.resetForm.invalid) return;

  this.authService.resetPassword(this.token!, this.resetForm.value.password).subscribe({
    next: (response) => {
      console.log('Success response:', response); // log server poruku
      Swal.fire('Success', 'Password has been reset.', 'success');
      this.router.navigate(['/login']); // po želji preusmeri korisnika na login
    },
    error: (err) => {
      console.error('Error response:', err); // log kompletan error objekat
      if (err.error) console.error('Server message:', err.error); // ako server vraća poruku
      Swal.fire('Error', 'Reset failed.', 'error');
    }
  });
}

}
