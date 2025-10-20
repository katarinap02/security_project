import { SignCSRRequest } from "./signCsr";

export interface CSRDTO {
  id: number;
  userId: number;
  caId: number;
  subject: string;
  publicKey: string; // ili Uint8Array, ako želiš da čuvaš binarne podatke
  requestedValidityDays?: number;
  status: 'PENDING' | 'APPROVED' | 'REJECTED';
  createdAt: string; // ISO string, može se parsirati u Date
  signRequest?: SignCSRRequest;
  signedCertificate?: any; 
}