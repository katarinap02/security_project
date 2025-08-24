export interface IssueCertificateDTO {
  commonName: string;
  surname: string;
  givenName: string;
  organization: string;
  organizationalUnit: string;
  country: string;
  email: string;
  uid?: string; 
  validFrom: Date;
  validTo: Date;
  type: string; 
  ownerEmail: string;
  issuerSerialNumber?: string;
}