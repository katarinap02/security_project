import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, FormControl, Validators, FormArray, AbstractControl, ValidationErrors, ReactiveFormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { MatInputModule } from '@angular/material/input';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatCheckboxModule } from '@angular/material/checkbox';

import { CertificateService } from '../../../service/certificate.service';
import { TemplateService } from '../../../service/template.service';
import { AuthService } from '../../../service/auth.service';
import { IssueCertificateDTO } from '../../../model/issuerCertificateDto';
import { Certificate } from '../../../model/certificate';
import { CertificateTemplateDTO } from '../../../model/certificateTemplateDto';
import { CertificateDTO } from '../../../model/certificateDto';
import { jwtDecode } from 'jwt-decode';

@Component({
  selector: 'app-issue-certificate-form-component',
  standalone: true,
  imports: [
    CommonModule,
    ReactiveFormsModule,  // 🔥 OVO JE KLJUČNO!
    RouterModule,
    MatCardModule,
    MatButtonModule,
    MatFormFieldModule,
    MatInputModule,
    MatCheckboxModule
  ],
  templateUrl: './IssueCertificateFormComponent.component.html',
  styleUrl: './IssueCertificateFormComponent.component.css',
})
export class IssueCertificateFormComponentComponent implements OnInit {

  certificateForm!: FormGroup;
  availableIssuers: CertificateDTO[] = [];
  availableTemplates: CertificateTemplateDTO[] = [];
  selectedTemplate: CertificateTemplateDTO | null = null;
  userRoles: number[] = [];
  pom: number = 0;
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
    private certificateService: CertificateService,
    private templateService: TemplateService,
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
      
      ownerEmail: [{ value: '', disabled: false }, [Validators.email]],
      validFrom: ['', Validators.required],
      validTo: ['', Validators.required],
      type: ['ROOT', Validators.required],
      issuerSerialNumber: [''],
      
      templateId: [''],
      
      keyUsage: this.fb.array([]),
      extendedKeyUsage: this.fb.array([]),
      subjectAlternativeNames: this.fb.array([])
    });

    this.proveriUloge();
    this.loadAvailableIssuers();
    this.initializeKeyUsageCheckboxes();
    this.initializeExtendedKeyUsageCheckboxes();
    
    // Issuer promene
    this.certificateForm.get('issuerSerialNumber')?.valueChanges.subscribe(issuerSerial => {
      if (issuerSerial) {
        this.loadTemplatesForIssuer(issuerSerial);
      } else {
        this.availableTemplates = [];
        this.selectedTemplate = null;
        this.certificateForm.patchValue({ templateId: '' });
      }
    });

    // Template promene
    this.certificateForm.get('templateId')?.valueChanges.subscribe(templateId => {
      if (templateId) {
        const numericId = typeof templateId === 'string' ? parseInt(templateId, 10) : templateId;
        this.applyTemplate(numericId);
      } else {
        this.clearTemplateApplication();
      }
    });

    // Provera validity kada se menja validTo
    this.certificateForm.get('validTo')?.valueChanges.subscribe(() => {
      this.validateMaxValidity();
    });
  }

  initializeKeyUsageCheckboxes(): void {
    const arr = this.keyUsageOptions.map(() => this.fb.control(false));
    this.certificateForm.setControl('keyUsage', this.fb.array(arr));
  }

  initializeExtendedKeyUsageCheckboxes(): void {
    const arr = this.extendedKeyUsageOptions.map(() => this.fb.control(false));
    this.certificateForm.setControl('extendedKeyUsage', this.fb.array(arr));
  }

  get keyUsageFormArray(): FormArray {
    return this.certificateForm.get('keyUsage') as FormArray;
  }

  get extendedKeyUsageFormArray(): FormArray {
    return this.certificateForm.get('extendedKeyUsage') as FormArray;
  }

  get sansFormArray(): FormArray {
    return this.certificateForm.get('subjectAlternativeNames') as FormArray;
  }

  getKeyUsageControl(index: number): FormControl {
    return this.keyUsageFormArray.at(index) as FormControl;
  }

  getExtendedKeyUsageControl(index: number): FormControl {
    return this.extendedKeyUsageFormArray.at(index) as FormControl;
  }

  getSanControl(index: number): FormControl {
    return this.sansFormArray.at(index) as FormControl;
  }

  addSAN(): void {
    const validator = this.selectedTemplate 
      ? [Validators.required, this.createSanValidator()] 
      : [Validators.required, this.sanFormatValidator.bind(this)];
    
    this.sansFormArray.push(this.fb.control('', validator));
  }

  sanFormatValidator(control: AbstractControl): ValidationErrors | null {
    const value = control.value;
    if (!value) return null;

    const parts = value.split(':');
    if (parts.length < 2) {
      return { invalidFormat: 'Must be in format TYPE:value (e.g., DNS:example.com)' };
    }

    const type = parts[0].toUpperCase().trim();
    const validTypes = ['DNS', 'IP', 'EMAIL', 'URI', 'DIRNAME'];

    if (!validTypes.includes(type)) {
      return { invalidType: `Type must be one of: ${validTypes.join(', ')}` };
    }

    const valueAfterColon = parts.slice(1).join(':');
    if (!valueAfterColon || valueAfterColon.trim() === '') {
      return { emptyValue: 'Value after type cannot be empty' };
    }

    if (type === 'EMAIL') {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(valueAfterColon)) {
        return { invalidEmail: 'Invalid email format' };
      }
    }

    if (type === 'IP') {
      const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
      if (!ipRegex.test(valueAfterColon)) {
        return { invalidIp: 'Invalid IP address format (e.g., 192.168.1.1)' };
      }
    }

    return null;
  }

  removeSAN(index: number): void {
    this.sansFormArray.removeAt(index);
  }

  loadAvailableIssuers(): void {
    this.certificateService.getCertificatesForUser().subscribe({
      next: (certificates: CertificateDTO[]) => {
        this.availableIssuers = certificates.filter(cert => 
          !cert.revoked && !cert.expired && cert.type !== 'END_ENTITY'
        );
      },
      error: (err) => {
        console.error('Greška pri učitavanju sertifikata:', err);
      }
    });
  }

  loadTemplatesForIssuer(issuerSerialNumber: string): void {
    this.templateService.getTemplatesByIssuer(issuerSerialNumber).subscribe({
      next: (templates: CertificateTemplateDTO[]) => {
        this.availableTemplates = templates;
      },
      error: (err) => {
        console.error('Greška pri učitavanju šablona:', err);
        this.availableTemplates = [];
      }
    });
  }

  applyTemplate(templateId: number): void {
    const template = this.availableTemplates.find(t => t.id === templateId);
    
    if (!template) {
      console.error('❌ Template not found! ID:', templateId);
      return;
    }

    this.selectedTemplate = template;
    console.log('✅ Applying template:', template.name);

    // Key Usage
    if (template.keyUsage && template.keyUsage.length > 0) {
      this.keyUsageOptions.forEach((option, i) => {
        const isSelected = template.keyUsage!.includes(option.value);
        const control = this.keyUsageFormArray.at(i);
        
        control.setValue(isSelected);
        
        if (isSelected) {
          control.disable({ emitEvent: false });
        } else {
          control.enable({ emitEvent: false });
        }
      });
    }

    // Extended Key Usage
    if (template.extendedKeyUsage && template.extendedKeyUsage.length > 0) {
      this.extendedKeyUsageOptions.forEach((option, i) => {
        const isSelected = template.extendedKeyUsage!.includes(option.value);
        const control = this.extendedKeyUsageFormArray.at(i);
        
        control.setValue(isSelected);
        
        if (isSelected) {
          control.disable({ emitEvent: false });
        } else {
          control.enable({ emitEvent: false });
        }
      });
    }

    // CN Validator
    if (template.commonNameRegex) {
      const cnControl = this.certificateForm.get('commonName');
      cnControl?.setValidators([
        Validators.required,
        this.createCnValidator(template.commonNameRegex)
      ]);
      cnControl?.updateValueAndValidity();
    }

    // Ažuriraj SVE postojeće SANs sa novim validatorom
    for (let i = 0; i < this.sansFormArray.length; i++) {
      const control = this.sansFormArray.at(i);
      control.setValidators([Validators.required, this.createSanValidator()]);
      control.updateValueAndValidity();
    }

    // Validacija validity perioda
    this.validateMaxValidity();
  }

  clearTemplateApplication(): void {
    this.selectedTemplate = null;
    
    // Resetuj CN validator
    const cnControl = this.certificateForm.get('commonName');
    cnControl?.setValidators([Validators.required]);
    cnControl?.updateValueAndValidity();
    
    // Omogući sve checkbox-ove
    this.keyUsageFormArray.controls.forEach(control => control.enable({ emitEvent: false }));
    this.extendedKeyUsageFormArray.controls.forEach(control => control.enable({ emitEvent: false }));
    
    // Resetuj SAN validatore
    for (let i = 0; i < this.sansFormArray.length; i++) {
      const control = this.sansFormArray.at(i);
      control.setValidators([Validators.required, this.sanFormatValidator.bind(this)]);
      control.updateValueAndValidity();
    }
  }

  // Custom CN validator
  createCnValidator(regex: string) {
    return (control: AbstractControl): ValidationErrors | null => {
      if (!control.value) return null;
      
      // 🔥 Ukloni višestruko escapovanje backslash-eva
      const cleanedRegex = regex.replace(/\\\\\\\\/g, '\\\\').replace(/\\\\/g, '\\');
      
      console.log('🔍 CN Validation:');
      console.log('  Original Regex:', regex);
      console.log('  Cleaned Regex:', cleanedRegex);
      console.log('  Value:', control.value);
      
      const pattern = new RegExp(cleanedRegex);
      const isValid = pattern.test(control.value);
      
      console.log('  Is Valid:', isValid);
      
      if (!isValid) {
        return { 
          cnPattern: `Common Name must match pattern: ${cleanedRegex}` 
        };
      }
      return null;
    };
  }

  // Custom SAN validator
  createSanValidator() {
    return (control: AbstractControl): ValidationErrors | null => {
      const basicValidation = this.sanFormatValidator(control);
      if (basicValidation) return basicValidation;

      if (this.selectedTemplate?.sanRegex) {
        // 🔥 Ukloni višestruko escapovanje backslash-eva
        const cleanedRegex = this.selectedTemplate.sanRegex
          .replace(/\\\\\\\\/g, '\\\\')
          .replace(/\\\\/g, '\\');
        
        console.log('🔍 SAN Validation:');
        console.log('  Original Regex:', this.selectedTemplate.sanRegex);
        console.log('  Cleaned Regex:', cleanedRegex);
        console.log('  Value:', control.value);
        
        const regex = new RegExp(cleanedRegex);
        const isValid = regex.test(control.value);
        
        console.log('  Is Valid:', isValid);
        
        if (!isValid) {
          return { 
            templateRegexMismatch: `SAN must match pattern: ${cleanedRegex}` 
          };
        }
      }

      return null;
    };
  }

  // Validacija maksimalnog perioda
  validateMaxValidity(): void {
    if (!this.selectedTemplate?.maxValidityDays) return;

    const validFromValue = this.certificateForm.get('validFrom')?.value;
    const validToValue = this.certificateForm.get('validTo')?.value;

    if (!validFromValue || !validToValue) return;

    const validFrom = new Date(validFromValue);
    const validTo = new Date(validToValue);
    const diffDays = Math.ceil((validTo.getTime() - validFrom.getTime()) / (1000 * 60 * 60 * 24));

    const validToControl = this.certificateForm.get('validTo');

    if (diffDays > this.selectedTemplate.maxValidityDays) {
      validToControl?.setErrors({
        ...validToControl.errors,
        maxValidity: `Maximum validity for this template is ${this.selectedTemplate.maxValidityDays} days`
      });
    } else {
      if (validToControl?.errors) {
        const { maxValidity, ...otherErrors } = validToControl.errors;
        if (Object.keys(otherErrors).length === 0) {
          validToControl.setErrors(null);
        } else {
          validToControl.setErrors(otherErrors);
        }
      }
    }
  }

  // Provera da li je forma zaista validna
  isFormValid(): boolean {
    // Osnovna validacija
    if (this.certificateForm.invalid) {
      console.log('❌ Form is invalid');
      this.logInvalidControls();
      return false;
    }

    // Proveri da li je barem jedan Key Usage selektovan
    const hasAnyKeyUsage = this.keyUsageFormArray.controls.some(c => c.value === true);
    if (!hasAnyKeyUsage) {
      console.log('❌ No key usage selected');
      return false;
    }

    return true;
  }

  // Debug funkcija
  logInvalidControls(): void {
    Object.keys(this.certificateForm.controls).forEach(key => {
      const control = this.certificateForm.get(key);
      if (control?.invalid) {
        console.log(`❌ ${key} is invalid:`, control.errors);
      }
    });

    this.sansFormArray.controls.forEach((control, i) => {
      if (control.invalid) {
        console.log(`❌ SAN[${i}] is invalid:`, control.errors);
      }
    });
  }

  onSubmit(): void {
    console.log('🚀 Submit clicked');

    if (!this.isFormValid()) {
      alert('⚠️ Molimo Vas popunite sva obavezna polja ispravno.');
      return;
    }

    // Dodatna template validacija
    if (this.selectedTemplate?.commonNameRegex) {
      const cn = this.certificateForm.get('commonName')?.value;
      
      // 🔥 Očisti regex
      const cleanedRegex = this.selectedTemplate.commonNameRegex
        .replace(/\\\\\\\\/g, '\\\\')
        .replace(/\\\\/g, '\\');
      
      const regex = new RegExp(cleanedRegex);
      if (!regex.test(cn)) {
        alert(`⚠️ Common Name mora odgovarati šablonu: ${cleanedRegex}`);
        return;
      }
    }

    if (this.selectedTemplate?.sanRegex && this.sansFormArray.length > 0) {
      // 🔥 Očisti regex
      const cleanedRegex = this.selectedTemplate.sanRegex
        .replace(/\\\\\\\\/g, '\\\\')
        .replace(/\\\\/g, '\\');
      
      const regex = new RegExp(cleanedRegex);
      for (let i = 0; i < this.sansFormArray.length; i++) {
        const sanValue = this.sansFormArray.at(i).value;
        if (!regex.test(sanValue)) {
          alert(`⚠️ SAN '${sanValue}' ne odgovara šablonu: ${cleanedRegex}`);
          return;
        }
      }
    }

    const formData: IssueCertificateDTO = this.certificateForm.getRawValue();

    // Sakupi Key Usage
    const selectedKeyUsages = this.keyUsageOptions
      .filter((_, i) => {
        const control = this.keyUsageFormArray.at(i);
        return control.value === true;
      })
      .map(option => option.value);
    
    formData.keyUsage = selectedKeyUsages.length > 0 ? selectedKeyUsages : undefined;

    // Sakupi Extended Key Usage
    const selectedExtendedKeyUsages = this.extendedKeyUsageOptions
      .filter((_, i) => {
        const control = this.extendedKeyUsageFormArray.at(i);
        return control.value === true;
      })
      .map(option => option.value);
    
    formData.extendedKeyUsage = selectedExtendedKeyUsages.length > 0 ? selectedExtendedKeyUsages : undefined;

    if (this.sansFormArray.length === 0) {
      formData.subjectAlternativeNames = undefined;
    }

    if (formData.type === 'ROOT') {
      delete formData.issuerSerialNumber;
    }

    delete (formData as any).templateId;

    console.log('📤 Sending certificate data:', formData);

    this.certificateService.issueCertificate(formData).subscribe({
      next: (response: Certificate) => {
        console.log('✅ Response:', response);
        alert('✅ Sertifikat je uspešno izdat! Serijski broj: ' + response.serialNumber);
        this.loadAvailableIssuers();
        this.resetForm();
      },
      error: (err) => {
        console.error('❌ Error:', err);
        alert('❌ Greška prilikom izdavanja sertifikata: ' + (err.error || err.message));
      }
    });
  }

  resetForm(): void {
    this.certificateForm.reset({ type: 'ROOT' });
    this.keyUsageFormArray.clear();
    this.extendedKeyUsageFormArray.clear();
    this.sansFormArray.clear();
    this.availableTemplates = [];
    this.selectedTemplate = null;
    this.initializeKeyUsageCheckboxes();
    this.initializeExtendedKeyUsageCheckboxes();
  }

  proveriUloge() {
    const token = localStorage.getItem('keycloakToken');

    if (token) {
      const decoded: any = jwtDecode(token);
      const roles = decoded.resource_access?.['my-app']?.roles || [];

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
    }
  }
}