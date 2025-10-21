import { Component, Optional } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClientModule } from '@angular/common/http';
import { PasswordManagerService, PasswordEntry } from '../service/password-manager.service';
import { MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';

interface PasswordRequestDTO {
  siteName: string;
  username: string;
  encryptedPassword: string;
  encryptedAesKey: string;
  iv: string;
}

@Component({
  selector: 'app-password-manager',
  standalone: true,
  imports: [CommonModule, FormsModule, HttpClientModule, MatDialogModule, MatButtonModule],
  templateUrl: './password-manager.component.html',
  styleUrls: ['./password-manager.component.css']
})
export class PasswordManagerComponent {
  siteName = '';
  username = '';
  password = '';
  publicKeyPem = '';
  privateKeyPem = '';
  message = '';

  passwords: PasswordEntry[] = [];
  decryptedPasswords: { [id: string]: string } = {};

  privateKey: CryptoKey | null = null;

  constructor(
    private pmService: PasswordManagerService,
    @Optional() private dialogRef?: MatDialogRef<PasswordManagerComponent>
  ) {}

  close() {
    this.dialogRef?.close();
  }

  loadPasswords() {
    this.pmService.getPasswords().subscribe({
      next: res => this.passwords = res,
      error: err => alert('Error loading passwords: ' + err.message)
    });
  }

  async addPassword() {
    if (!this.publicKeyPem || !this.password) {
      alert('Public key or password missing!');
      return;
    }

    // 1️⃣ Generiši AES ključ
    const aesKey = await window.crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );

    // 2️⃣ Šifruj lozinku AES-om
    const encoder = new TextEncoder();
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encryptedPasswordBuffer = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      aesKey,
      encoder.encode(this.password)
    );
    const encryptedPassword = btoa(String.fromCharCode(...new Uint8Array(encryptedPasswordBuffer)));
    const ivBase64 = btoa(String.fromCharCode(...iv));

    // 3️⃣ Eksportuj AES ključ i šifruj RSA javnim ključem
    const rawAesKey = await window.crypto.subtle.exportKey('raw', aesKey);

    const rsaKey = await window.crypto.subtle.importKey(
      'spki',
      this.pemToArrayBuffer(this.publicKeyPem),
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['encrypt']
    );

    const encryptedAesKeyBuffer = await window.crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      rsaKey,
      rawAesKey
    );
    const encryptedAesKey = btoa(String.fromCharCode(...new Uint8Array(encryptedAesKeyBuffer)));

    // 4️⃣ Pošalji backend-u
    const dto: PasswordRequestDTO = {
      siteName: this.siteName,
      username: this.username,
      encryptedPassword,
      encryptedAesKey,
      iv: ivBase64
    };

    await this.pmService.addPassword(dto).toPromise();

    this.siteName = '';
    this.username = '';
    this.password = '';
    this.loadPasswords();
  }

  async loadPrivateKey(event: any) {
    const file = event.target.files[0];
    const pem = await file.text();
    const binaryDer = Uint8Array.from(
      atob(pem.replace(/-----.*?-----/g, '').replace(/\s+/g, '')),
      c => c.charCodeAt(0)
    );

    this.privateKey = await window.crypto.subtle.importKey(
      'pkcs8',
      binaryDer.buffer,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      true,
      ['decrypt']
    );
  }

  async decryptPassword(entry: PasswordEntry) {
    if (!this.privateKey) {
      alert('Load private key first!');
      return;
    }

    try {
      const encryptedAesKeyBytes = Uint8Array.from(atob(entry.encryptedAesKey), c => c.charCodeAt(0));
      const rawAesKey = await window.crypto.subtle.decrypt(
        { name: 'RSA-OAEP' },
        this.privateKey,
        encryptedAesKeyBytes
      );

      const aesKey = await window.crypto.subtle.importKey(
        'raw',
        rawAesKey,
        'AES-GCM',
        true,
        ['decrypt']
      );

      const encryptedPasswordBytes = Uint8Array.from(atob(entry.encryptedPassword), c => c.charCodeAt(0));
      const iv = Uint8Array.from(atob(entry.iv), c => c.charCodeAt(0));

      const decryptedBuffer = await window.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        aesKey,
        encryptedPasswordBytes
      );

      this.decryptedPasswords[entry.id!.toString()] = new TextDecoder().decode(decryptedBuffer);

    } catch (e) {
      alert('Error decrypting password: ' + e);
    }
  }

  private pemToArrayBuffer(pem: string): ArrayBuffer {
  // Ukloni header, footer i sve whitespace
  const cleanPem = pem
    .replace(/-----BEGIN [\w\s]+-----/, '')
    .replace(/-----END [\w\s]+-----/, '')
    .replace(/\s+/g, '');
  const binary = atob(cleanPem);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}


  deletePassword(id: number) {
    if (!confirm('Da li ste sigurni da želite da obrišete ovu lozinku?')) return;

    this.pmService.deletePassword(id).subscribe({
      next: () => {
        this.passwords = this.passwords.filter(p => p.id !== id);
        delete this.decryptedPasswords[id.toString()];
      },
      error: err => alert('Error deleting password: ' + err.message)
    });
  }

  async loadPublicKey(event: any) {
    const file = event.target.files[0];
    this.publicKeyPem = await file.text();
  }

}
