import { CertificateOwner } from "./certificatOwner";

export interface Certificate {
  id: number;
  serialNumber: string;
  type: string;
  validFrom: Date;
  validTo: Date;
  isRevoked: boolean;
  ownerEmail: string;
  issuerSerialNumber: string | null; 
}