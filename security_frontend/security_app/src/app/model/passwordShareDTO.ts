export interface PasswordShareDTO {
  passwordEntryId: number;
  targetUserId: number;
  encryptedAesKey: string;
  iv: string;
}
