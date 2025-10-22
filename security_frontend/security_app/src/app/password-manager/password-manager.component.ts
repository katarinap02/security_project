import { Component, Optional } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { HttpClientModule } from '@angular/common/http';
import { PasswordManagerService, PasswordEntry } from '../service/password-manager.service';
import { MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatButtonModule } from '@angular/material/button';
import { SharedPassword } from '../model/sharedPassword';

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

  sharedPasswords: SharedPassword[] = [];
  decryptedSharedPasswords: { [id: string]: string } = {};

  privateKey: CryptoKey | null = null;

  selectedPasswordId: number | undefined = undefined;
  selectedUserId: number | null = null;
  shareTargetPublicKeyPem: string = '';
  shareMessage = '';
  shareSuccess = false;

  users: { id: number; email: string }[] = [];

  constructor(
    private pmService: PasswordManagerService,
    @Optional() private dialogRef?: MatDialogRef<PasswordManagerComponent>
  ) {}

  ngOnInit() {
    this.loadPasswords();
    this.loadSharedPasswords();
    this.loadUsers();
  }

  close() {
    this.dialogRef?.close();
  }

  // --- CRUD METHODS ---

  public async addPassword() {
    if (!this.siteName || !this.username || !this.password || !this.publicKeyPem) {
      alert('All fields and public key are required!');
      return;
    }

    try {
      // 1️⃣ Generiši AES ključ
      const aesKey = await window.crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
      );

      // 2️⃣ Šifruj lozinku AES-om
      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      const encoder = new TextEncoder();
      const encryptedBuffer = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        aesKey,
        encoder.encode(this.password)
      );

      const encryptedPassword = btoa(String.fromCharCode(...new Uint8Array(encryptedBuffer)));

      // 3️⃣ Šifruj AES ključ javnim ključem korisnika
      const publicKey = await window.crypto.subtle.importKey(
        'spki',
        this.pemToArrayBuffer(this.publicKeyPem),
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        false,
        ['encrypt']
      );

      const rawAesKey = await window.crypto.subtle.exportKey('raw', aesKey);
      const encryptedAesKeyBuffer = await window.crypto.subtle.encrypt(
        { name: 'RSA-OAEP' },
        publicKey,
        rawAesKey
      );
      const encryptedAesKey = btoa(String.fromCharCode(...new Uint8Array(encryptedAesKeyBuffer)));
      const ivBase64 = btoa(String.fromCharCode(...iv));

      // 4️⃣ Pošalji backend-u
      const dto: PasswordEntry = {
        siteName: this.siteName,
        username: this.username,
        encryptedPassword,
        encryptedAesKey,
        iv: ivBase64
      };

      const saved = await this.pmService.addPassword(dto).toPromise();
      if (saved) {          // <-- proveravamo da li postoji
        this.passwords.push(saved);
        // reset inputa
        this.siteName = '';
        this.username = '';
        this.password = '';
        this.publicKeyPem = '';
        this.message = 'Password added successfully!';
      } else {
        alert('Failed to add password.');
      }

    } catch (e) {
      alert('Error adding password: ' + e);
    }
  }

  public async loadPublicKey(event: any) {
    const file = event.target.files[0];
    this.publicKeyPem = await file.text();
  }

  public async loadPrivateKey(event: any) {
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

  public deletePassword(id: number) {
    if (!confirm('Da li ste sigurni da želite da obrišete ovu lozinku?')) return;

    this.pmService.deletePassword(id).subscribe({
      next: () => {
        this.passwords = this.passwords.filter(p => p.id !== id);
        delete this.decryptedPasswords[id.toString()];
      },
      error: err => alert('Error deleting password: ' + err.message)
    });
  }

  public async decryptPassword(entry: PasswordEntry) {
    if (!this.privateKey) {
      alert('Load private key first!');
      return;
    }

    try {
      const aesKeyBytes = Uint8Array.from(atob(entry.encryptedAesKey), c => c.charCodeAt(0));
      const rawAesKey = await window.crypto.subtle.decrypt({ name: 'RSA-OAEP' }, this.privateKey, aesKeyBytes);
      const aesKey = await window.crypto.subtle.importKey('raw', rawAesKey, 'AES-GCM', true, ['decrypt']);

      const encryptedPasswordBytes = Uint8Array.from(atob(entry.encryptedPassword), c => c.charCodeAt(0));
      const iv = Uint8Array.from(atob(entry.iv), c => c.charCodeAt(0));
      const decryptedBuffer = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, encryptedPasswordBytes);

      this.decryptedPasswords[entry.id!.toString()] = new TextDecoder().decode(decryptedBuffer);

    } catch (e) {
      alert('Error decrypting password: ' + e);
    }
  }

  

public async sharePassword() {
  if (!this.selectedPasswordId || !this.selectedUserId || !this.shareTargetPublicKeyPem) {
    this.shareMessage = 'Select password, user, and load recipient public key!';
    this.shareSuccess = false;
    return;
  }

  const entry = this.passwords.find(p => p.id === this.selectedPasswordId);
  if (!entry || !this.privateKey) {
    this.shareMessage = 'Missing entry or private key!';
    this.shareSuccess = false;
    return;
  }

  try {
    // 1️⃣ Dekripcija AES ključa vlasnika
    const aesKeyBytes = Uint8Array.from(atob(entry.encryptedAesKey), c => c.charCodeAt(0));
    const rawAesKey = await window.crypto.subtle.decrypt({ name: 'RSA-OAEP' }, this.privateKey, aesKeyBytes);

    // 2️⃣ Učitaj javni ključ korisnika kome se deli
    const recipientPublicKey = await window.crypto.subtle.importKey(
      'spki',
      this.pemToArrayBuffer(this.shareTargetPublicKeyPem),
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['encrypt']
    );

    // 3️⃣ Šifruj AES ključ javnim ključem primaoca
    const encryptedForRecipient = await window.crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      recipientPublicKey,
      rawAesKey
    );

    const encryptedAesKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(encryptedForRecipient)));

    // 4️⃣ Pošalji backendu
    // ⚠️ Koristimo IV iz originalne lozinke, NE novi IV
    await this.pmService.sharePassword({
      passwordEntryId: entry.id!,
      targetUserId: this.selectedUserId!,
      encryptedAesKey: encryptedAesKeyBase64,
      iv: entry.iv // <-- koristi originalni IV
    }).toPromise();

    this.shareMessage = 'Password shared successfully!';
    this.shareSuccess = true;

  } catch (e) {
    console.error(e);
    this.shareMessage = 'Error sharing password: ' + e;
    this.shareSuccess = false;
  }
}


  // --- Helpers ---
  private pemToArrayBuffer(pem: string): ArrayBuffer {
    const clean = pem.replace(/-----.*?-----/g, '').replace(/\s+/g, '');
    const binary = atob(clean);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }

  // --- Load users ---
  private loadUsers() {
    this.pmService.getUsers().subscribe({
      next: res => this.users = res,
      error: err => alert('Error loading users: ' + err.message)
    });
  }

  // --- Load passwords ---
  public loadPasswords() {
    this.pmService.getPasswords().subscribe({
      next: res => this.passwords = res,
      error: err => alert('Error loading passwords: ' + err.message)
    });
  }

  // --- Load shared passwords ---
  private loadSharedPasswords() {
    this.pmService.getSharedPasswords().subscribe({
      next: res => {
        this.sharedPasswords = res; // svi podaci su već tu
      },
      error: err => alert('Error loading shared passwords: ' + err.message)
    });
  }


  public async loadSharePublicKey(event: any) {
    const file = event.target.files[0];
    this.shareTargetPublicKeyPem = await file.text();
  }

  private ivToUint8Array(iv: string): Uint8Array {
  try {
    // Ako izgleda kao Base64
    const bytes = Uint8Array.from(atob(iv), c => c.charCodeAt(0));
    return new Uint8Array(bytes.buffer); // <- obavezno da bude običan ArrayBuffer
  } catch {
    // Ako nije Base64, koristimo TextEncoder
    const encoded = new TextEncoder().encode(iv);
    return new Uint8Array(encoded.buffer);
  }
}



public async decryptSharedPassword(share: SharedPassword) {
  if (!this.privateKey) {
    alert('Load your private key first!');
    return;
  }

  // --- Provera da li su svi podaci prisutni ---
  if (!share.encryptedAesKey?.trim() || !share.encryptedPassword?.trim() || !share.iv?.trim()) {
    alert('Shared password is missing data!');
    return;
  }

  try {
    // --- Helper: Base64 string u ArrayBuffer ---
    const base64ToArrayBuffer = (base64: string): ArrayBuffer => {
      const binary = atob(base64.replace(/\s+/g, ''));
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      return bytes.buffer;
    };

    // 1️⃣ Dekripcija AES ključa RSA-om koristeći privatni ključ korisnika
    const encryptedAesKeyBytes = base64ToArrayBuffer(share.encryptedAesKey);
    const rawAesKey = await window.crypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      this.privateKey,
      encryptedAesKeyBytes
    );

    const aesKey = await window.crypto.subtle.importKey(
      'raw',
      rawAesKey,
      { name: 'AES-GCM' },
      true,
      ['decrypt']
    );

    // 2️⃣ Dekripcija lozinke AES-GCM
    const encryptedPasswordBytes = base64ToArrayBuffer(share.encryptedPassword);

    // IV dekodiran iz Base64
    const ivBytes = Uint8Array.from(atob(share.iv), c => c.charCodeAt(0));

    const decryptedBuffer = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: ivBytes },
      aesKey,
      encryptedPasswordBytes
    );

    // 3️⃣ Sačuvaj dekriptovanu lozinku
    this.decryptedSharedPasswords[share.id.toString()] = new TextDecoder().decode(decryptedBuffer);

  } catch (e) {
    console.error(e);
    alert('Error decrypting shared password: ' + e);
  }
}

}
