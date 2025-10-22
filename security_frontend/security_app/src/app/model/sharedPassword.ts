export interface SharedPassword {
  id: number;
  passwordEntryId: number;
  encryptedAesKey: string;   // RSA šifrovan AES ključ
  createdBy: string;         // email osobe koja je share-ovala
  siteName: string;          // iz DTO (PasswordEntry)
  username: string;          // iz DTO (PasswordEntry)
  encryptedPassword: string; // iz DTO (PasswordEntry)
  iv: string;                // iz DTO (PasswordShare)
}
