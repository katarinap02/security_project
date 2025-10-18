import { Component, Optional } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClient, HttpClientModule } from '@angular/common/http';
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
  userEmail = '';
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
    private http: HttpClient,
    @Optional() private dialogRef?: MatDialogRef<PasswordManagerComponent>
  ) {}

  // -------------------------------
  // 🔹 Zatvaranje dijaloga
  // -------------------------------
  close() {
    if (this.dialogRef) {
      this.dialogRef.close();
    }
  }

  // -------------------------------
  // 🔹 Učitavanje postojećih lozinki
  // -------------------------------
  loadPasswords() {
    this.pmService.getPasswords(this.userEmail).subscribe(res => this.passwords = res);
  }

  // -------------------------------
  // 🔹 Dodavanje nove lozinke
  // -------------------------------
  async addPassword() {
  if (!this.publicKeyPem || !this.password) {
    alert('Public key or password missing!');
    return;
  }

  await this.pmService.addPassword({
    ownerEmail: this.userEmail,
    siteName: this.siteName,
    username: this.username,
    encryptedPassword: this.password // plaintext, biće šifrovana u servisu
  }, this.publicKeyPem).toPromise();

  this.siteName = '';
  this.username = '';
  this.password = '';
  this.loadPasswords();
}



  // -------------------------------
  // 🔹 Generisanje RSA para ključeva
  // -------------------------------
  async generateKeys() {
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256'
      },
      true,
      ['encrypt', 'decrypt']
    );

    const publicKey = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);
    const privateKey = await window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey);

    this.publicKeyPem = this.arrayBufferToPem(publicKey, 'PUBLIC KEY');
    this.privateKeyPem = this.arrayBufferToPem(privateKey, 'PRIVATE KEY');
    this.privateKey = keyPair.privateKey;

    this.message = 'RSA par ključeva generisan uspešno!';
  }
  // -------------------------------
  // 🔹 Učitavanje privatnog ključa iz .pem fajla
  // -------------------------------
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

  // -------------------------------
  // 🔹 Dekripcija lozinke
  // -------------------------------
  async decryptPassword(entry: PasswordEntry) {
    if (!this.privateKey) {
      alert('Load private key first!');
      return;
    }

    const encryptedBytes = Uint8Array.from(atob(entry.encryptedPassword), c => c.charCodeAt(0));
    const decrypted = await window.crypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      this.privateKey,
      encryptedBytes
    );

    this.decryptedPasswords[entry.id!.toString()] = new TextDecoder().decode(decrypted);
  }

  // -------------------------------
  // 🔹 Helper: konverzija u PEM format
  // -------------------------------
  private arrayBufferToPem(buffer: ArrayBuffer, label: string): string {
    const binary = String.fromCharCode(...new Uint8Array(buffer));
    const base64 = btoa(binary);
    const formatted = base64.match(/.{1,64}/g)?.join('\n');
    return `-----BEGIN ${label}-----\n${formatted}\n-----END ${label}-----`;
  }
}
