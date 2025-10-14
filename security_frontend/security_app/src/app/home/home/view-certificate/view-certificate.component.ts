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
    'issuerEmail',
    'issuerSerialNumber',
    'validFrom',
    'validTo',
    'isRevoked',
    'revocationReason',
    'revocationDate',
    'expired',
    'actions'
  ];

  dataSource = new MatTableDataSource<CertificateDTO>([]);
  loading = true;

  @ViewChild(MatSort) sort!: MatSort;
  @ViewChild(MatPaginator) paginator!: MatPaginator;

  constructor(private certificateService: CertificateService) {}

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


  downloadCertificate(cert: CertificateDTO): void {
    console.log('Download clicked for', cert.serialNumber);
  }
}
