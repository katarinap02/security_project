export interface CertificateTemplateDTO {
  id?: number;
  name: string;
  description?: string;
  issuerSerialNumber: string;
  commonNameRegex?: string;
  sanRegex?: string;
  maxValidityDays: number;
  keyUsage?: string[];
  extendedKeyUsage?: string[];
}