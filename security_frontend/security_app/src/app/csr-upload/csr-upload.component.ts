import { Component } from '@angular/core';
import { CsrService } from '../service/csr.service';
import { CertificateService } from '../service/certificate.service';
import { CommonModule } from '@angular/common';
import { HttpClientModule } from '@angular/common/http';
import { FormsModule } from '@angular/forms';
import { CSRDTO } from '../model/csr';
import { CA } from '../model/ca';
import { SignCSRRequest } from '../model/signCsr';


@Component({
  selector: 'app-csr-upload',
  standalone: true,
  imports: [CommonModule, HttpClientModule, FormsModule],
  templateUrl: './csr-upload.component.html',
  styleUrls: ['./csr-upload.component.css']
})
export class CsrUploadComponent {
  selectedFile: File | null = null;
  message: string = '';
  success: boolean = false;

  userCsrs: CSRDTO[] = [];
  availableCAs: CA[] = [];

  constructor(private csrService: CsrService, private certificateService: CertificateService) {}

  ngOnInit() {
    this.loadUserCSRs();
    this.loadAvailableCAs();
  }

  onFileSelected(event: any) {
    this.selectedFile = event.target.files[0];
  }

  submit() {
    if (!this.selectedFile) {
      alert('⚠️ Molimo izaberite CSR fajl.');
      return;
    }

    this.csrService.uploadCSR(this.selectedFile).subscribe({
      next: () => {
        this.message = '✅ CSR uspešno upload-ovan!';
        this.success = true;
        this.selectedFile = null;
        this.loadUserCSRs(); // osveži listu CSRs
      },
      error: (err) => {
        console.error(err);
        this.message = '❌ Došlo je do greške pri uploadu CSR-a.';
        this.success = false;
      }
    });
  }

  
  loadUserCSRs() {
  this.csrService.getUserCSRs().subscribe({
    next: (csrs) => {
      this.userCsrs = csrs.map(csr => ({
        ...csr,
        signRequest: csr.signRequest ?? {  // ako već postoji, ne dodaj
          caId: 0,
          commonName: '',
          surname: '',
          givenName: '',
          organization: '',
          organizationalUnit: '',
          country: '',
          email: ''
        }
      }));
    },
    error: (err) => {
      console.error('Greška pri učitavanju CSR-ova:', err);
      this.userCsrs = [];
    }
  });
}


  loadAvailableCAs() {
    this.csrService.getAllCAs().subscribe({
      next: cas => this.availableCAs = cas,
      error: err => console.error('Ne mogu da dobijem CA-ove', err)
    });
  }

  
  signCertificate(csr: any): void {
  if (!csr.signRequest.caId) {
    alert('⚠️ Molimo izaberite CA.');
    return;
  }

  this.csrService.signCSR(csr.id, csr.signRequest).subscribe({
    next: (cert: any) => {
      csr.signedCertificate = cert; // za dugme Download
      this.downloadCertificate(cert);
    },
    error: (err) => {
      alert('Greška pri potpisivanju: ' + err.error);
    }
  });
}


  downloadCertificate(certificate: any): void {
    const serialNumber = certificate.serialNumber;
    this.certificateService.downloadCertificate(serialNumber).subscribe({
      next: (file: Blob) => {
        const url = window.URL.createObjectURL(file);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${serialNumber}.cer`;
        a.click();
        window.URL.revokeObjectURL(url);
      },
      error: (err) => {
        console.error('Download failed:', err);
      }
    });
  }
}
