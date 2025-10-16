import { Component, OnInit, ViewChild } from '@angular/core';
import { CommonModule } from '@angular/common';
import { MatTableModule } from '@angular/material/table';
import { MatCardModule } from '@angular/material/card';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatChipsModule } from '@angular/material/chips';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { MatSortModule, MatSort } from '@angular/material/sort';
import { MatPaginatorModule, MatPaginator } from '@angular/material/paginator';
import { MatTableDataSource } from '@angular/material/table';
import { CertificateDTO } from '../../../model/certificateDto';
import { CertificateService } from '../../../service/certificate.service';
import { RevokeCertificateDialogComponent } from '../revoke-certificate-dialog/revoke-certificate-dialog.component';
import { RevokeCertificateDTO } from '../../../model/revokDto';
import { MatDialog } from '@angular/material/dialog';

@Component({
  selector: 'app-view-certificate',
  standalone: true,
  imports: [
    CommonModule,
    MatTableModule,
    MatCardModule,
    MatButtonModule,
    MatIconModule,
    MatChipsModule,
    MatTooltipModule,
    MatProgressSpinnerModule,
    MatSortModule,
    MatPaginatorModule
  ],
  templateUrl: './view-certificate.component.html',
  styleUrls: ['./view-certificate.component.css'],
})
export class ViewCertificateComponent implements OnInit {

  displayedColumns: string[] = [
    'serialNumber',
    'type',
    'ownerEmail',
    'issuerSerialNumber',
    'validFrom',
    'validTo',
    'isRevoked',
    'revocationReason',
    'revocationDate',
    'expired',
    'actions',
    'actions2'
  ];

  dataSource = new MatTableDataSource<CertificateDTO>([]);
  loading = true;

  @ViewChild(MatSort) sort!: MatSort;
  @ViewChild(MatPaginator) paginator!: MatPaginator;

  constructor(private certificateService: CertificateService, private dialog: MatDialog) {}

  ngOnInit(): void {
    this.loadCertificates();
  }

  loadCertificates(): void {
    this.certificateService.getCertificatesForUser().subscribe({
      next: (list) => {
        console.log(list)
        const processed = list.map(c => ({
          ...c,
          validFrom: new Date(c.validFrom),
          validTo: new Date(c.validTo),
          expired: new Date(c.validTo) < new Date()
        }));
        this.dataSource.data = processed;
        this.dataSource.sort = this.sort;
        this.dataSource.paginator = this.paginator;
        this.loading = false;
      },
      error: (err) => {
        console.error('Failed to load certificates', err);
        this.loading = false;
      }
    });
  }

  formatDate(date: Date | undefined): string {
  if (!date) return '-';
  return new Intl.DateTimeFormat('en-US', { 
    year: 'numeric', month: 'short', day: '2-digit',
    hour: '2-digit', minute: '2-digit'
  }).format(new Date(date));
}


  downloadCertificate(certificate: CertificateDTO): void {
  const serialNumber= certificate.serialNumber;
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

revokeCertificate(cert: any): void {
  const dialogRef = this.dialog.open(RevokeCertificateDialogComponent, {
    width: '400px',
    data: { serialNumber: cert.serialNumber }
  });

  dialogRef.afterClosed().subscribe((result: RevokeCertificateDTO | null) => {
    if (result) {
      this.certificateService.revokeCertificate(result).subscribe({
        next: () => {
          alert('Certificate successfully revoked.');
          this.loadCertificates();
        },
        error: err => {
          console.error('Error revoking certificate:', err);
          alert('Failed to revoke certificate.');
        }
      });
    }
  });
}


}
