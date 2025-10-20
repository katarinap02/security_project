import { Injectable } from '@angular/core';
import { CanActivate, ActivatedRouteSnapshot, RouterStateSnapshot, Router } from '@angular/router';
import jwt_decode from 'jwt-decode';
import { AuthService } from '../service/auth.service';

interface JwtPayload {
  resource_access?: {
    [key: string]: {
      roles?: string[];
    }
  }
}

@Injectable({
  providedIn: 'root'
})
export class AuthGuard implements CanActivate {

  constructor(private authService: AuthService, private router: Router) {}

  canActivate(route: ActivatedRouteSnapshot, state: RouterStateSnapshot): boolean {
    const token = this.authService.getToken();

    if (!token) {
      // Nije ulogovan → preusmeravanje na login
      this.router.navigate(['/login']);
      return false;
    }

    let userRoles: string[] = [];
    try {
      const decoded = (jwt_decode as any)(token) as JwtPayload;

      // Ako JWT nema resource_access ili my-app → tretiramo ga kao neulogovanog
      if (!decoded.resource_access || !decoded.resource_access['my-app']) {
        this.router.navigate(['/login']);
        return false;
      }

      userRoles = decoded.resource_access['my-app'].roles || [];
      console.log('Očekivane role za ovu rutu:', route.data['roles']);
      console.log('Role korisnika iz JWT:', userRoles);

    } catch (err) {
      console.error('JWT decoding failed', err);
      this.router.navigate(['/login']);
      return false;
    }

    const expectedRoles = route.data['roles'] as string[]; // role definisane u ruti

    if (!expectedRoles || expectedRoles.length === 0) {
      // Ako ruta nema definisane role → svi ulogovani imaju pristup
      return true;
    }

    // Provera da li korisnik ima bar jednu od očekivanih uloga
    const hasRole = expectedRoles.some(role => userRoles.includes(role));
    if (!hasRole) {
      alert('Nemate dozvolu za pristup ovoj stranici!');
      return false; // ruta ostaje zaključana
    }

    return true;
  }
}
