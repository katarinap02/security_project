import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, FormsModule, ReactiveFormsModule, Validators, FormArray } from '@angular/forms';
import { CertificateService } from '../../../service/certificate.service';
import { IssueCertificateDTO } from '../../../model/issuerCertificateDto';
import { Certificate } from '../../../model/certificate';
import { RouterModule } from '@angular/router';
import { MatInputModule } from '@angular/material/input';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatCheckboxModule } from '@angular/material/checkbox';
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
    MatCheckboxModule,
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

  // Key Usage opcije
  keyUsageOptions = [
    { value: 'digitalSignature', label: 'Digital Signature' },
    { value: 'nonRepudiation', label: 'Non Repudiation' },
    { value: 'keyEncipherment', label: 'Key Encipherment' },
    { value: 'dataEncipherment', label: 'Data Encipherment' },
    { value: 'keyAgreement', label: 'Key Agreement' },
    { value: 'keyCertSign', label: 'Certificate Sign' },
    { value: 'cRLSign', label: 'CRL Sign' }
  ];

  // Extended Key Usage opcije
  extendedKeyUsageOptions = [
    { value: 'serverAuth', label: 'TLS Web Server Authentication' },
    { value: 'clientAuth', label: 'TLS Web Client Authentication' },
    { value: 'codeSigning', label: 'Code Signing' },
    { value: 'emailProtection', label: 'Email Protection' },
    { value: 'timeStamping', label: 'Time Stamping' },
    { value: 'ocspSigning', label: 'OCSP Signing' }
  ];

  constructor(
    private fb: FormBuilder,
    private certificateService: CertificateService,
    public authService: AuthService
  ) { }

  ngOnInit(): void {
    this.certificateForm = this.fb.group({
      // Subject podaci
      commonName: ['', Validators.required],
      surname: ['', Validators.required],
      givenName: ['', Validators.required],
      organization: ['', Validators.required],
      organizationalUnit: ['', Validators.required],
      country: ['', Validators.required],
      email: ['', [Validators.required, Validators.email]],
      
      // Technical details
      ownerEmail: [{ value: '', disabled: false }, [Validators.email]],
      validFrom: ['', Validators.required],
      validTo: ['', Validators.required],
      type: ['ROOT', Validators.required],
      issuerSerialNumber: [''],
      
      // Ekstenzije
      keyUsage: this.fb.array([]), // FormArray za checkbox-ove
      extendedKeyUsage: this.fb.array([]),
      subjectAlternativeNames: this.fb.array([]) // Array za SANs
    });

    this.proveriUloge();
    this.loadAvailableIssuers();
    this.initializeKeyUsageCheckboxes();
    this.initializeExtendedKeyUsageCheckboxes();
  }

  // Inicijalizuj Key Usage checkbox-ove
  initializeKeyUsageCheckboxes(): void {
    const arr = this.keyUsageOptions.map(() => this.fb.control(false));
    this.certificateForm.setControl('keyUsage', this.fb.array(arr));
  }

  // Inicijalizuj Extended Key Usage checkbox-ove
  initializeExtendedKeyUsageCheckboxes(): void {
    const arr = this.extendedKeyUsageOptions.map(() => this.fb.control(false));
    this.certificateForm.setControl('extendedKeyUsage', this.fb.array(arr));
  }

  // Getter za Key Usage FormArray
  get keyUsageFormArray(): FormArray {
    return this.certificateForm.get('keyUsage') as FormArray;
  }

  // Getter za Extended Key Usage FormArray
  get extendedKeyUsageFormArray(): FormArray {
    return this.certificateForm.get('extendedKeyUsage') as FormArray;
  }

  // Getter za SANs FormArray
  get sansFormArray(): FormArray {
    return this.certificateForm.get('subjectAlternativeNames') as FormArray;
  }

  // Helper metoda za pristup pojedinačnim kontrolama (type-safe)
  getKeyUsageControl(index: number) {
    return this.keyUsageFormArray.at(index) as any;
  }

  getExtendedKeyUsageControl(index: number) {
    return this.extendedKeyUsageFormArray.at(index) as any;
  }

  getSanControl(index: number) {
    return this.sansFormArray.at(index) as any;
  }

  // Dodaj novi SAN input
  addSAN(): void {
    this.sansFormArray.push(this.fb.control('', [Validators.required, this.sanFormatValidator]));
  }

  // ✅ CUSTOM VALIDATOR za SAN format
  sanFormatValidator(control: any) {
    const value = control.value;
    if (!value) return null; // Prazan input je OK (required će ga uhvatiti)

    // Mora biti format: TYPE:value
    const parts = value.split(':');
    if (parts.length < 2) {
      return { invalidFormat: 'Must be in format TYPE:value (e.g., DNS:example.com)' };
    }

    const type = parts[0].toUpperCase().trim();
    const validTypes = ['DNS', 'IP', 'EMAIL', 'URI', 'DIRNAME'];

    if (!validTypes.includes(type)) {
      return { invalidType: `Type must be one of: ${validTypes.join(', ')}` };
    }

    const valueAfterColon = parts.slice(1).join(':'); // Slučaj za URI koji može imati više :
    if (!valueAfterColon || valueAfterColon.trim() === '') {
      return { emptyValue: 'Value after type cannot be empty' };
    }

    // Dodatna validacija za EMAIL
    if (type === 'EMAIL') {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(valueAfterColon)) {
        return { invalidEmail: 'Invalid email format' };
      }
    }

    // Dodatna validacija za IP
    if (type === 'IP') {
      const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
      if (!ipRegex.test(valueAfterColon)) {
        return { invalidIp: 'Invalid IP address format (e.g., 192.168.1.1)' };
      }
    }

    return null; // Validno
  }

  // Ukloni SAN input
  removeSAN(index: number): void {
    this.sansFormArray.removeAt(index);
  }

  loadAvailableIssuers(): void {
    this.certificateService.getCertificatesForUser().subscribe({
      next: (certificates: CertificateDTO[]) => {
        this.availableIssuers = certificates.filter(cert => 
          !cert.revoked && !cert.expired && cert.type !== 'END_ENTITY'
        );
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

    // Konvertuj Key Usage checkboxes u array stringova
    const selectedKeyUsages = this.keyUsageOptions
      .filter((_, i) => this.keyUsageFormArray.at(i).value)
      .map(option => option.value);
    
    formData.keyUsage = selectedKeyUsages.length > 0 ? selectedKeyUsages : undefined;

    // Konvertuj Extended Key Usage checkboxes u array stringova
    const selectedExtendedKeyUsages = this.extendedKeyUsageOptions
      .filter((_, i) => this.extendedKeyUsageFormArray.at(i).value)
      .map(option => option.value);
    
    formData.extendedKeyUsage = selectedExtendedKeyUsages.length > 0 ? selectedExtendedKeyUsages : undefined;

    // SANs već su array stringova
    if (this.sansFormArray.length === 0) {
      formData.subjectAlternativeNames = undefined;
    }

    if (formData.type === 'ROOT') {
      delete formData.issuerSerialNumber;
    }

    console.log('📤 Sending certificate data:', formData);

    this.certificateService.issueCertificate(formData).subscribe({
      next: (response: Certificate) => {
        console.log('✅ Odgovor sa servera:', response);
        alert('Sertifikat je uspešno izdat! Serijski broj: ' + response.serialNumber);
        this.loadAvailableIssuers();
        this.resetForm();
      },
      error: (err) => {
        console.error('❌ Došlo je do greške:', err);
        alert('Greška prilikom izdavanja sertifikata: ' + (err.error || err.message));
      }
    });
  }

  resetForm(): void {
    this.certificateForm.reset({ type: 'ROOT' });
    this.keyUsageFormArray.clear();
    this.extendedKeyUsageFormArray.clear();
    this.sansFormArray.clear();
    this.initializeKeyUsageCheckboxes();
    this.initializeExtendedKeyUsageCheckboxes();
  }

  proveriUloge() {
    const token = localStorage.getItem('keycloakToken');

    if (token) {
      const decoded: any = jwtDecode(token);
      const roles = decoded.resource_access?.['my-app']?.roles || [];

      console.log('Role iz tokena:', roles);

      if (roles.includes('ROLE_ADMIN')) {
        this.pom = 1;
      } 
      else if (roles.includes('ROLE_CA_USER')) {
        this.pom = 2;

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
}