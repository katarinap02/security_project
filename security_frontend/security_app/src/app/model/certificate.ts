import { CertificateOwner } from "./certificatOwner";

export interface Certificate {
  id: number;
  serialNumber: string;
  validFrom: Date;
  validTo: Date;
  type: string; 
  revoked: boolean;
  issuer: Certificate | null; 
  owner: CertificateOwner;
}