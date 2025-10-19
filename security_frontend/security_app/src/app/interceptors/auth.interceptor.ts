import { HttpEvent, HttpHandlerFn, HttpInterceptorFn, HttpRequest } from '@angular/common/http';
import { Observable } from 'rxjs';

/**
 * Interceptor koji automatski dodaje Keycloak token
 * u Authorization header svakog HTTP zahteva.
 */
export const authInterceptor: HttpInterceptorFn = (
  req: HttpRequest<unknown>,
  next: HttpHandlerFn
): Observable<HttpEvent<unknown>> => {/*

  // ✅ Uzmi token iz localStorage-a (gde ga čuvaš posle login-a)
  const token = localStorage.getItem('keycloakToken');

  if (token) {
    // ✅ Kloniraj zahtev i dodaj Authorization header
    const clonedRequest = req.clone({
      setHeaders: {
        Authorization: `Bearer ${token}`
      }
    });
    return next(clonedRequest);
  }*/

  // 🔸 Ako token ne postoji — prosledi zahtev bez izmene
  return next(req);
};
