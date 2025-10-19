import { Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class TwoFactorService {
  // inicijalno false
  private showTwoFactorSubject = new BehaviorSubject<boolean>(false);

  // Observable koji komponente mogu da slušaju
  showTwoFactor$ = this.showTwoFactorSubject.asObservable();

  // metoda za promenu stanja
  setShowTwoFactor(value: boolean) {
    this.showTwoFactorSubject.next(value);
  }
}
