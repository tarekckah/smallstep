package org.example;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import java.io.IOException;
import java.security.Security;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

public class CAToken {
  private String caUrl;
  private String caFingerprint;
  private String provisionerName;
  private PKCS10CertificationRequest csr;
  private String token;

  public CAToken(String caUrl, String caFingerprint, PKCS10CertificationRequest csr,
                 String provisionerName, String jwk) throws IOException {
    this.caUrl = caUrl;
    this.caFingerprint = caFingerprint;
    this.csr = csr;
    this.provisionerName = provisionerName;

    // Add BouncyCastleProvider
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

    // Extract SANs from CSR
    List<GeneralName> sans = extractSubjectAlternativeNames(csr);

    // Create JWT
    this.token = Jwts.builder()
      .setAudience(this.caUrl + "/1.0/sign")
      .claim("sha", this.caFingerprint)
      .setExpiration(Date.from(Instant.now().plus(5, ChronoUnit.MINUTES)))
      .setIssuedAt(Date.from(Instant.now()))
      .setNotBefore(Date.from(Instant.now()))
      .setId(UUID.randomUUID().toString())
      .setIssuer(this.provisionerName)
      .claim("sans", sans)
      .setSubject(csr.getSubject().toString())
      .signWith(Keys.hmacShaKeyFor(jwk.getBytes()), SignatureAlgorithm.ES256)
      .compact();
  }

  public String getToken() {
    return token;
  }

  private List<GeneralName> extractSubjectAlternativeNames(PKCS10CertificationRequest csr) throws IOException {
    List<GeneralName> sans = new ArrayList<>();
    byte[] extensionBytes = csr.getEncoded();
    ASN1Sequence seq = ASN1Sequence.getInstance(extensionBytes);
    for (int i = 0; i < seq.size(); i++) {
      ASN1TaggedObject tagged = (ASN1TaggedObject) seq.getObjectAt(i);
      if (tagged.getTagNo() == 0) {
        Extensions exts = Extensions.getInstance(tagged, false);
        Extension sanExt = exts.getExtension(Extension.subjectAlternativeName);
        if (sanExt != null) {
          ASN1Encodable names = GeneralName.getInstance(
            sanExt.getParsedValue()).getName();
         sans.add((GeneralName) names);
        }
      }
    }
    return sans;
  }
}
