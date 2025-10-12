import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ReactiveFormsModule, FormBuilder, FormGroup, Validators } from '@angular/forms';
import { HttpClient, HttpEventType, HttpClientModule } from '@angular/common/http';

export interface CA {
  id: number;
  name: string;
  maxCertificateDuration: number;
  isRoot: boolean;
}

@Component({
  selector: 'app-csr-upload',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule, HttpClientModule],
  templateUrl: './csr-upload.component.html',
  styleUrls: ['./csr-upload.component.css']
})
export class CsrUploadComponent {
  csrForm: FormGroup;
  cas: CA[] = [
    { id: 1, name: 'CA One', maxCertificateDuration: 365, isRoot: true },
    { id: 2, name: 'CA Two', maxCertificateDuration: 180, isRoot: false }
  ];
  selectedFile: File | null = null;
  message: string = '';
  success: boolean = false;

  constructor(private fb: FormBuilder, private http: HttpClient) {
    this.csrForm = this.fb.group({
      csrFile: [null, Validators.required],
      caId: ['', Validators.required],
      validityDays: [1, [Validators.required, Validators.min(1)]]
    });
  }

  onFileChange(event: any) {
    const file = event.target.files?.[0];
    if (file) {
      this.selectedFile = file;
      this.csrForm.patchValue({ csrFile: file });
    }
  }

  onCaChange() {
    const caId = Number(this.csrForm.value.caId);
    const ca = this.cas.find(c => c.id === caId);
    if (ca) {
      const currentDays = this.csrForm.value.validityDays;
      this.csrForm.patchValue({ validityDays: Math.min(currentDays, ca.maxCertificateDuration) });
    }
  }

  get selectedCA(): CA | undefined {
    const caId = Number(this.csrForm.value.caId);
    return this.cas.find(c => c.id === caId);
  }

  submit() {
  if (!this.selectedFile || !this.csrForm.valid) return;

  const formData = new FormData();
  formData.append('file', this.selectedFile);
  formData.append('caId', this.csrForm.value.caId);
  formData.append('validityDays', this.csrForm.value.validityDays);

  const token = localStorage.getItem('jwtToken'); 

  this.http.post('http://localhost:8080/api/csr/upload', formData, {
    observe: 'events',
    reportProgress: true,
    headers: token ? { Authorization: `Bearer ${token}` } : {}
  }).subscribe({
    next: event => {
      if (event.type === HttpEventType.Response) {
        this.message = 'Zahtev uspešno poslat!';
        this.success = true;
        this.csrForm.reset();
        this.selectedFile = null;
      }
    },
    error: err => {
      console.error(err);
      if (err.status === 401) {
        this.message = 'Niste autorizovani da pošaljete zahtev.';
      } else {
        this.message = 'Došlo je do greške pri slanju.';
      }
      this.success = false;
    }
  });
}
}