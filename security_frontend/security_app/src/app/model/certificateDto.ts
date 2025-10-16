export interface CertificateDTO {
  serialNumber: string;
  type: string;                             
  validFrom: Date;                
  validTo: Date;                  
  revoked: boolean;             
  revocationReason?: string;      
  revocationDate?: Date;          
  ownerEmail: string;             
  issuerSerialNumber?: string;    
  issuerEmail?: string
  expired?: boolean
}