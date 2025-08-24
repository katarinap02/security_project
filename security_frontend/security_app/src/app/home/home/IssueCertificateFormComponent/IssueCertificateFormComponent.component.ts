import { ChangeDetectionStrategy, Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, FormsModule, ReactiveFormsModule, Validators } from '@angular/forms';
import { CertificateService } from '../../../service/certificate.service';
import { IssueCertificateDTO } from '../../../model/issuerCertificateDto';
import { Certificate } from '../../../model/certificate';
import { RouterModule } from '@angular/router';
import { MatInputModule } from '@angular/material/input';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { CommonModule } from '@angular/common';
import { AuthService } from '../../../service/auth.service';

@Component({
  selector: 'app-issue-certificate-form-component',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    MatCardModule,
    MatButtonModule,
    MatFormFieldModule,
    MatInputModule,
    RouterModule,
    ReactiveFormsModule
  ],
  templateUrl: './IssueCertificateFormComponent.component.html',
  styleUrl: './IssueCertificateFormComponent.component.css',
})
export class IssueCertificateFormComponentComponent implements OnInit {

  certificateForm!: FormGroup;
  userRoles: number[] = [];
  pom: number = 0;
  userEmail: string | null = localStorage.getItem('email');

  constructor(
    private fb: FormBuilder,
    private certificateService: CertificateService,
    public authService: AuthService
  ) { }

  ngOnInit(): void {
    this.certificateForm = this.fb.group({
      commonName: ['', Validators.required],
      surname: ['', Validators.required],
      givenName: ['', Validators.required],
      organization: ['', Validators.required],
      organizationalUnit: ['', Validators.required],
      country: ['', Validators.required],
      email: ['', [Validators.required, Validators.email]],
      ownerEmail: [{ value: '', disabled: false }, [Validators.email]], // inicijalno enabled
      validFrom: ['', Validators.required],
      validTo: ['', Validators.required],
      type: ['ROOT', Validators.required],
      issuerSerialNumber: ['']
    });

    this.proveriUloge();
  }

  onSubmit(): void {
    if (this.certificateForm.invalid) {
      alert('Molimo Vas popunite sva obavezna polja ispravno.');
      return;
    }

    const formData: IssueCertificateDTO = this.certificateForm.getRawValue(); 
    // getRawValue() uzima i disabled polja

    if (formData.type === 'ROOT') {
      delete formData.issuerSerialNumber;
    }

    this.certificateService.issueCertificate(formData).subscribe({
      next: (response: Certificate) => {
        console.log('Odgovor sa servera:', response);
        alert('Sertifikat je uspešno izdat! Serijski broj: ' + response.serialNumber);

        this.certificateForm.reset({ type: 'ROOT' });
      },
      error: (err) => {
        console.error('Došlo je do greške:', err);
        alert('Greška prilikom izdavanja sertifikata: ' + err.error);
      }
    });
  }

  proveriUloge() {
    if (this.userEmail) {
      this.authService.getRoleIdsByEmail(this.userEmail).subscribe({
        next: (roleIds) => {
          this.userRoles = roleIds;
          console.log('ID-jevi uloga za ovog korisnika su:', this.userRoles);

          if (this.userRoles.includes(1)) {
            this.pom = 1;
          }
          else if (this.userRoles.includes(2)) {
            this.pom = 2;

            // disable + set value za ownerEmail
            this.certificateForm.get('ownerEmail')?.disable();
            this.certificateForm.patchValue({
              ownerEmail: this.userEmail,
              type: 'INTERMEDIATE'
            });
          }
        },
        error: (err) => {
          console.error('Nije moguće dobaviti uloge:', err);
        }
      });
    }
  }

}
