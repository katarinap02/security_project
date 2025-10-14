export interface CertificateDTO {
  serialNumber: string;
  type: string;                             
  validFrom: Date;                
  validTo: Date;                  
  isRevoked: boolean;             
  revocationReason?: string;      
  revocationDate?: Date;          
  ownerEmail: string;             
  issuerSerialNumber?: string;    
  issuerEmail?: string
  expired?: boolean
}