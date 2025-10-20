import { Component } from '@angular/core';
import { CsrService } from '../service/csr.service';
import { CertificateService } from '../service/certificate.service';
import { CommonModule } from '@angular/common';
import { HttpClientModule } from '@angular/common/http';
import { FormsModule } from '@angular/forms';
import { CSRDTO } from '../model/csr';
import { CA } from '../model/ca';
import { SignCSRRequest } from '../model/signCsr';
import { CertificateDTO } from '../model/certificateDto';
import { IssueCertificateDTO } from '../model/issuerCertificateDto';


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
  availableIssuers: CertificateDTO[] = [];
  

  constructor(private csrService: CsrService, private certificateService: CertificateService) {}

  ngOnInit() {
    this.loadUserCSRs();
    this.loadAvailableIssuers();
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
          issuerSerialNumber: '',          // obavezno polje
          commonName: '',
          surname: '',
          givenName: '',
          organization: '',
          organizationalUnit: '',
          country: '',
          email: '',
          validFrom: new Date(),           // opcionalno, default vrednost
          validTo: new Date(new Date().setFullYear(new Date().getFullYear() + 1)),
          type: 'END_ENTITY',              // možeš staviti default
          ownerEmail: ''                   // ili email korisnika
        }
      }));
    },
    error: (err) => {
      console.error('Greška pri učitavanju CSR-ova:', err);
      this.userCsrs = [];
    }
  });
}



  loadAvailableIssuers(): void {
      this.certificateService.getIssuersForUser().subscribe({
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


    signCertificate(csr: CSRDTO) {
      if (!csr.signRequest?.issuerSerialNumber) {
        alert('⚠️ Molimo izaberite issuer sertifikat.');
        return;
      }

      if (!csr.csrPem) {
        alert('⚠️ CSR sadržaj nije učitan.');
        return;
      }

      const dto: IssueCertificateDTO = {
        commonName: csr.signRequest.commonName,
        surname: csr.signRequest.surname,
        givenName: csr.signRequest.givenName,
        organization: csr.signRequest.organization,
        organizationalUnit: csr.signRequest.organizationalUnit,
        country: csr.signRequest.country,
        email: csr.signRequest.email,
        validFrom: csr.signRequest!.validFrom ? new Date(csr.signRequest!.validFrom) : new Date(),
        validTo: csr.signRequest!.validTo ? new Date(csr.signRequest!.validTo) : new Date(new Date().setFullYear(new Date().getFullYear() + 1)),
        type: 'END_ENTITY', // ili po potrebi
        ownerEmail: csr.signRequest.ownerEmail || '', // može se defaultovati
        issuerSerialNumber: csr.signRequest.issuerSerialNumber,
        templateId: csr.signRequest.templateId,
        subjectAlternativeNames: csr.signRequest.subjectAlternativeNames,
        keyUsage: csr.signRequest.keyUsage,
        extendedKeyUsage: csr.signRequest.extendedKeyUsage
      };

      this.certificateService.issueCertificateFromCSR(csr.csrPem, dto).subscribe({
        next: (signedCertificate) => {
          this.message = '✅ CSR je uspešno potpisan!';
          this.success = true;
          csr.signedCertificate = signedCertificate;
          csr.signRequest = undefined; // ukloni formu nakon potpisivanja
        },
        error: (err) => {
          console.error('Greška pri potpisivanju CSR-a:', err);
          this.message = '❌ Došlo je do greške pri potpisivanju CSR-a.';
          this.success = false;
        }
      });
    }

}
