import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClientModule } from '@angular/common/http';
import { PasswordManagerService, PasswordEntry } from '../service/password-manager.service';
import { MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';

@Component({
  selector: 'app-password-manager',
  standalone: true,
  imports: [CommonModule, FormsModule, HttpClientModule, MatDialogModule, MatButtonModule],
  templateUrl: './password-manager.component.html',
  styleUrls: ['./password-manager.component.css']
})
export class PasswordManagerComponent {
  userEmail = 'mandicmarija27@gmail.com';
  siteName = '';
  username = '';
  password = '';
  publicKeyPem = '';

  passwords: PasswordEntry[] = [];
  decryptedPasswords: { [id: string]: string } = {};

  privateKey: CryptoKey | null = null;

  constructor(private pmService: PasswordManagerService,
              private dialogRef: MatDialogRef<PasswordManagerComponent>) {}

  close() {
    this.dialogRef.close();
  }

  loadPasswords() {
    this.pmService.getPasswords(this.userEmail).subscribe(res => this.passwords = res);
  }

  async addPassword() {
    if (!this.publicKeyPem) { alert('Provide public key!'); return; }

    await this.pmService.addPassword({
      ownerEmail: this.userEmail,
      siteName: this.siteName,
      username: this.username,
      encryptedPassword: ''
    }, this.publicKeyPem).toPromise();

    this.siteName = '';
    this.username = '';
    this.password = '';
    this.loadPasswords();
  }

  async loadPrivateKey(event: any) {
    const file = event.target.files[0];
    const pem = await file.text();
    const binaryDer = Uint8Array.from(atob(pem.replace(/-----.*?-----/g, '').replace(/\s+/g, '')), c => c.charCodeAt(0));

    this.privateKey = await window.crypto.subtle.importKey(
      'pkcs8',
      binaryDer.buffer,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      true,
      ['decrypt']
    );
  }

  async decryptPassword(entry: PasswordEntry) {
    if (!this.privateKey) { alert('Load private key first!'); return; }

    const encryptedBytes = Uint8Array.from(atob(entry.encryptedPassword), c => c.charCodeAt(0));
    const decrypted = await window.crypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      this.privateKey,
      encryptedBytes
    );

    this.decryptedPasswords[entry.id!.toString()] = new TextDecoder().decode(decrypted);
  }
}
