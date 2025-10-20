// src/app/model/sign-csr-request.ts
export interface SignCSRRequest {
  caId: number;           // ID izabrane CA
  commonName?: string;    // CN
  surname?: string;       // SN
  givenName?: string;     // GIVENNAME
  organization?: string;  // O
  organizationalUnit?: string; // OU
  country?: string;       // C
  email?: string;         // E
}
