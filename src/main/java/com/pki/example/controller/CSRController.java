package com.pki.example.controller;

import com.pki.example.model.CA;
import com.pki.example.model.CSR;
import com.pki.example.repository.CARepository;
import com.pki.example.repository.CSRRepository;
import com.pki.example.service.CSRService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@RestController
@RequestMapping("/api/csr")
public class CSRController {
    @Autowired
    private CSRService csrService;
    @Autowired
    private CARepository caRepository;


    @GetMapping()
    public ResponseEntity<List<CSR>> getAllCSRs() {
        return ResponseEntity.ok(csrService.getAll());
    }

    @GetMapping("/{id}")
    public ResponseEntity<CSR> getCSR(@PathVariable Long id) {
        return ResponseEntity.ok(csrService.getCSRById(id));
    }


    @PostMapping("/upload")
    public ResponseEntity<CSR> uploadCSR(@RequestParam("file") MultipartFile csrFile,
                                         @RequestParam("caId") Long caId,
                                         @RequestParam("validityDays") int validityDays) {

        try{
            CA ca = caRepository.findById(caId).orElseThrow(() -> new IllegalArgumentException("Ne postoji odabrana CA"));
            CSR csr = csrService.uploadCSR(csrFile, ca, validityDays);
            return ResponseEntity.ok(csr);
        }catch (Exception e){
            return ResponseEntity.badRequest().body(null);
        }
    }


    // CA pregleda sve PENDING CSR-ove
    @GetMapping("/ca/{caId}/pending")
    public List<CSR> getPendingForCa(@PathVariable Long caId) {
        return csrService.getPendingRequestsForCa(caId);
    }

    // CA odobrava zahtev
    @PostMapping("/{csrId}/approve")
    public CSR approveRequest(
            @PathVariable Long csrId,
            @RequestParam int validityDays
    ) {
        return csrService.approveRequest(csrId, validityDays);
    }

    // CA odbija zahtev
    @PostMapping("/{csrId}/reject")
    public CSR rejectRequest(
            @PathVariable Long csrId,
            @RequestParam String reason
    ) {
        return csrService.rejectRequest(csrId, reason);
    }

    // korisnik vidi svoje CSR-ove
    @GetMapping("/user/{userId}")
    public List<CSR> getUserRequests(@PathVariable Integer userId) {
        return csrService.getUserRequests(userId);
    }
}
