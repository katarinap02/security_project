import { ComponentFixture, TestBed } from '@angular/core/testing';

import { CsrUploadComponent } from './csr-upload.component';

describe('CsrUploadComponent', () => {
  let component: CsrUploadComponent;
  let fixture: ComponentFixture<CsrUploadComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [CsrUploadComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(CsrUploadComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
