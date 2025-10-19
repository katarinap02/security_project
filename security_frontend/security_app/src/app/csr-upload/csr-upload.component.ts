import { Component } from '@angular/core';
import { CsrService } from '../service/csr.service';
import { CommonModule } from '@angular/common';
import { HttpClientModule } from '@angular/common/http';

@Component({
  selector: 'app-csr-upload',
  standalone: true,
  imports: [CommonModule, HttpClientModule], // <--- CommonModule mora da bude ovde
  templateUrl: './csr-upload.component.html',
  styleUrls: ['./csr-upload.component.css']
})
export class CsrUploadComponent {
  selectedFile: File | null = null;
  message: string = '';
  success: boolean = false;

  constructor(private csrService: CsrService) {}

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
        alert(this.message);
        this.selectedFile = null;
      },
      error: err => {
        console.error(err);
        this.message = '❌ Došlo je do greške pri uploadu CSR-a.';
        this.success = false;
        alert(this.message);
      }
    });
  }
}
