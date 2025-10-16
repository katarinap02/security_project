import { Component, Inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatDialogRef, MAT_DIALOG_DATA, MatDialogModule } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatButtonModule } from '@angular/material/button';
import { RevocationReason, RevokeCertificateDTO } from '../../../model/revokDto';

@Component({
  selector: 'app-revoke-certificate-dialog',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    MatDialogModule,
    MatFormFieldModule,
    MatInputModule,
    MatSelectModule,
    MatButtonModule
  ],
  templateUrl: './revoke-certificate-dialog.component.html',
  styleUrl: './revoke-certificate-dialog.component.css',
})
export class RevokeCertificateDialogComponent {
  serialNumber: string;
  reason: RevocationReason | null = null;
  comment: string = '';
  reasons = Object.values(RevocationReason);

  constructor(
    public dialogRef: MatDialogRef<RevokeCertificateDialogComponent>,
    @Inject(MAT_DIALOG_DATA) public data: { serialNumber: string }
  ) {
    this.serialNumber = data.serialNumber;
  }

  cancel(): void {
    this.dialogRef.close(null);
  }

  confirmRevoke(): void {
    const dto: RevokeCertificateDTO = {
      serialNumber: this.serialNumber,
      reason: this.reason!,
      comment: this.comment
    };
    this.dialogRef.close(dto);
  }
}
