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
import { jwtDecode } from 'jwt-decode';
import { CertificateDTO } from '../../../model/certificateDto';

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
  availableIssuers: CertificateDTO[] = [];
  userRoles: number[] = [];
  pom: number = 0;
  userEmail: string | null = localStorage.getItem('sub');


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
    console.log(this.userEmail)

    this.proveriUloge();
    this.loadAvailableIssuers();
  }

  loadAvailableIssuers(): void {
    
    this.certificateService.getCertificatesForUser().subscribe({
      next: (certificates: CertificateDTO[]) => {
        console.log('Svi sertifikati:', certificates);
        
        this.availableIssuers = certificates.filter(cert => {
          const isValid = !cert.revoked && !cert.expired && cert.type !== 'END_ENTITY';
          
          if (isValid) {
          }
          
          return isValid;
        });

        console.log('🔐 Dostupni issuers:', this.availableIssuers.length);
      },
      error: (err) => {
        console.error('Greška pri učitavanju sertifikata:', err);
      }
    });
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
        this.loadAvailableIssuers();
        this.certificateForm.reset({ type: 'ROOT' });
      },
      error: (err) => {
        console.error('Došlo je do greške:', err);
        alert('Greška prilikom izdavanja sertifikata: ' + err.error);
      }
    });
  }

  proveriUloge() {
  const token = localStorage.getItem('keycloakToken');

  if (token) {
    const decoded: any = jwtDecode(token);
    const roles = decoded.resource_access?.['my-app']?.roles || [];

    console.log('Role iz tokena:', roles);

    // ROLE_ADMIN → 1
    // ROLE_CA_USER → 2
    if (roles.includes('ROLE_ADMIN')) {
      this.pom = 1;
    } 
    else if (roles.includes('ROLE_CA_USER')) {
      this.pom = 2;

      // disable + set value za ownerEmail ako je CA korisnik
      this.certificateForm.get('ownerEmail')?.disable();
      this.certificateForm.patchValue({
        ownerEmail: this.userEmail,
        type: 'INTERMEDIATE'
      });
    } else {
      this.pom = 0;
    }
  } else {
    console.warn('Token nije pronađen u localStorage.');
  }
}
/*
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
  }*/

}
