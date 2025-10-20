import { ChangeDetectionStrategy, Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, FormsModule, ReactiveFormsModule, Validators, FormArray } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { MatInputModule } from '@angular/material/input';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { RouterModule, Router } from '@angular/router';
import { CertificateService } from '../../../service/certificate.service';
import { CertificateDTO } from '../../../model/certificateDto';
import { TemplateService } from '../../../service/template.service';
import { CertificateTemplateDTO } from '../../../model/certificateTemplateDto';

@Component({
  selector: 'app-create-template',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    ReactiveFormsModule,
    MatCardModule,
    MatButtonModule,
    MatFormFieldModule,
    MatInputModule,
    MatCheckboxModule,
    RouterModule
  ],
  templateUrl:  './create-template.component.html',
  styleUrl: './create-template.component.css',
})
export class CreateTemplateComponent implements OnInit {

  templateForm!: FormGroup;
  availableIssuers: CertificateDTO[] = [];
  userEmail: string | null = localStorage.getItem('sub');

  keyUsageOptions = [
    { value: 'digitalSignature', label: 'Digital Signature' },
    { value: 'nonRepudiation', label: 'Non Repudiation' },
    { value: 'keyEncipherment', label: 'Key Encipherment' },
    { value: 'dataEncipherment', label: 'Data Encipherment' },
    { value: 'keyAgreement', label: 'Key Agreement' },
    { value: 'keyCertSign', label: 'Certificate Sign' },
    { value: 'cRLSign', label: 'CRL Sign' }
  ];

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
    private templateService: TemplateService,
    private certificateService: CertificateService,
    private router: Router
  ) {}

  ngOnInit(): void {
    this.templateForm = this.fb.group({
      name: ['', Validators.required],
      description: [''],
      issuerSerialNumber: ['', Validators.required],
      commonNameRegex: ['', [this.regexValidator]],
      sanRegex: ['', [this.sanRegexValidator]],
      maxValidityDays: ['', [Validators.required, Validators.min(1), Validators.max(3650)]],
      keyUsage: this.fb.array([]),
      extendedKeyUsage: this.fb.array([])
    });

    this.initializeKeyUsageCheckboxes();
    this.initializeExtendedKeyUsageCheckboxes();
    this.loadAvailableIssuers();
  }

  // CUSTOM VALIDATOR za Common Name Regex
  regexValidator(control: any) {
    const value = control.value;
    if (!value) return null; // Prazan regex je OK (opciono polje)

    try {
      new RegExp(value); // Pokušaj da kompajliraš regex
      return null; 
    } catch (e) {
      return { invalidRegex: 'Invalid regular expression syntax' };
    }
  }

  sanRegexValidator(control: any) {
    const value = control.value;
    if (!value) return null; // Prazan je OK

    // SAN regex mora početi sa: DNS:, IP:, EMAIL:, URI:, ili DIRNAME:
    const validPrefixes = ['DNS:', 'IP:', 'EMAIL:', 'URI:', 'DIRNAME:'];
    const hasValidPrefix = validPrefixes.some(prefix => value.startsWith(prefix));

    if (!hasValidPrefix) {
      return { 
        invalidSanPrefix: `SAN regex must start with: ${validPrefixes.join(', ')}` 
      };
    }

    // Proveri da li je deo posle : validan regex
    const regexPart = value.substring(value.indexOf(':') + 1);
    if (!regexPart || regexPart.trim() === '') {
      return { emptySanRegex: 'Regex pattern after type cannot be empty' };
    }

    try {
      new RegExp(regexPart);
      return null; // Validan
    } catch (e) {
      return { invalidSanRegex: 'Invalid regular expression syntax after type' };
    }
  }

  initializeKeyUsageCheckboxes(): void {
    const arr = this.keyUsageOptions.map(() => this.fb.control(false));
    this.templateForm.setControl('keyUsage', this.fb.array(arr));
  }

  initializeExtendedKeyUsageCheckboxes(): void {
    const arr = this.extendedKeyUsageOptions.map(() => this.fb.control(false));
    this.templateForm.setControl('extendedKeyUsage', this.fb.array(arr));
  }

  get keyUsageFormArray(): FormArray {
    return this.templateForm.get('keyUsage') as FormArray;
  }

  get extendedKeyUsageFormArray(): FormArray {
    return this.templateForm.get('extendedKeyUsage') as FormArray;
  }

  getKeyUsageControl(index: number) {
    return this.keyUsageFormArray.at(index) as any;
  }

  getExtendedKeyUsageControl(index: number) {
    return this.extendedKeyUsageFormArray.at(index) as any;
  }

  loadAvailableIssuers(): void {
    this.certificateService.getCertificatesForUser().subscribe({
      next: (certificates: CertificateDTO[]) => {
        // Samo CA sertifikati (ROOT, INTERMEDIATE) koji nisu revoked/expired
        this.availableIssuers = certificates.filter(cert => 
          !cert.revoked && !cert.expired && cert.type !== 'END_ENTITY'
        );
        console.log(' Available issuers for template:', this.availableIssuers.length);
      },
      error: (err) => {
        console.error('Error loading certificates:', err);
      }
    });
  }

  onSubmit(): void {
    if (this.templateForm.invalid) {
      alert('Please fill in all required fields correctly.');
      return;
    }

    const formData = this.templateForm.getRawValue();

    // Konvertuj Key Usage checkboxes u array
    const selectedKeyUsages = this.keyUsageOptions
      .filter((_, i) => this.keyUsageFormArray.at(i).value)
      .map(option => option.value);

    // Konvertuj Extended Key Usage checkboxes u array
    const selectedExtendedKeyUsages = this.extendedKeyUsageOptions
      .filter((_, i) => this.extendedKeyUsageFormArray.at(i).value)
      .map(option => option.value);

    const templateDTO: CertificateTemplateDTO = {
  name: formData.name,
  description: formData.description,
  issuerSerialNumber: formData.issuerSerialNumber,
  commonNameRegex: formData.commonNameRegex || undefined,
  sanRegex: formData.sanRegex || undefined,
  maxValidityDays: formData.maxValidityDays,
  keyUsage: selectedKeyUsages.length > 0 ? selectedKeyUsages : undefined,
  extendedKeyUsage: selectedExtendedKeyUsages.length > 0 ? selectedExtendedKeyUsages : undefined
};


    console.log('Creating template:', templateDTO);

    this.templateService.createTemplate(templateDTO).subscribe({
      next: (response) => {
        console.log('✅ Template created:', response);
        alert('Template created successfully!');
        this.router.navigate(['/certificates']);
      },
      error: (err) => {
        console.error('Error creating template:', err);
        alert('Failed to create template: ' + (err.error?.error || err.message));
      }
    });
  }
}