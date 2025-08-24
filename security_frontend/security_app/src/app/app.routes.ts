import { RouterModule, Routes } from '@angular/router';
import { HomeComponent } from './home/home/home.component';
import { LoginComponent } from './home/home/login/login.component';
import { RegistrationComponent } from './home/home/registration/registration.component';
import { NgModule } from '@angular/core';
import { ProfileComponent } from './profile/profile.component';
import { ForgotPasswordComponent } from './home/home/forgot-password/forgot-password.component';
import { ResetPasswordComponent } from './home/home/reset-password/reset-password.component';
import { HttpClientModule } from '@angular/common/http';
import { ReactiveFormsModule } from '@angular/forms';
import { IssueCertificateFormComponentComponent } from './home/home/IssueCertificateFormComponent/IssueCertificateFormComponent.component';

export const routes: Routes = [
  { path: '', component: HomeComponent },
  { path: 'login', component: LoginComponent },
  { path: 'register', component: RegistrationComponent },
  { path: 'profile', component: ProfileComponent },
  { path: 'forgot-password', component: ForgotPasswordComponent},
  { path: 'reset-password', component: ResetPasswordComponent },
  { path: 'add-cerficate', component: IssueCertificateFormComponentComponent }
];

@NgModule({
  imports: [RouterModule.forRoot(routes),
    HttpClientModule, ReactiveFormsModule
  ],
  exports: [RouterModule]
})
export class AppRoutingModule {}