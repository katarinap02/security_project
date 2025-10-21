export interface CSRDTO {
  id: number;
  userId: number;
  caId: number;
  subject: string;
  publicKey: string; // ili Uint8Array, ako čuvamo binarne podatke
  requestedValidityDays?: number;
  status: 'PENDING' | 'APPROVED' | 'REJECTED';
  createdAt: string; // ISO string
  // signRequest je sada plain object sa poljima potrebnim za izdavanje
  signRequest?: {
    issuerSerialNumber: string;
    commonName: string;
    surname: string;
    givenName: string;
    organization: string;
    organizationalUnit: string;
    country: string;
    email: string;
    validFrom?: Date;
    validTo?: Date;
    ownerEmail?: string;
    templateId?: number;
    subjectAlternativeNames?: string[];
    keyUsage?: string[];
    extendedKeyUsage?: string[];
  };
  signedCertificate?: any; 
  csrPem?: string; // sadržaj CSR fajla u PEM formatu
}
