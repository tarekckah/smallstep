package org.example;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.io.FileReader;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.Security;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;

public class CAToken {
  private String caUrl;
  private String caFingerprint;
  private String provisionerName;
  private CSR csr;
  private String token;

  public CAToken(String caUrl, String caFingerprint, CSR csr,
                 String provisionerName, String jwk)
    throws Exception {
    this.caUrl = caUrl;
    this.caFingerprint = caFingerprint;
    this.csr = csr;
    this.provisionerName = provisionerName;

    // Add BouncyCastleProvider
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

//    JWK jwkParsed = JWK.parse(jwk);
//    ECKey ecKey = (ECKey) jwkParsed;
//    PrivateKey privateKey = ecKey.toPrivateKey();

//    byte[] privateKeyBytes = Files.readAllBytes(Paths.get("C:/Users/ahmed/.step/secrets/root_ca_key"));
//    byte[] decodedPrivateKeyBytes = Base64.getDecoder().decode(privateKeyBytes);
//    PrivateKey privateKey = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(decodedPrivateKeyBytes));

//    String privateKeyPem = new String(Files.readAllBytes(Paths.get("C:/Users/ahmed/.step/secrets/root_ca_key")));
//
//    // Remove PEM headers and footers
//    String privateKeyPEM = privateKeyPem
//      .replace("-----BEGIN PRIVATE KEY-----", "")
//      .replace("-----END PRIVATE KEY-----", "")
//      .replaceAll("\\s", "");
//
//    // Decode Base64-encoded private key bytes
//    byte[] decodedPrivateKeyBytes = Base64.getDecoder().decode(privateKeyPEM);
//
//    // Create PrivateKey object from decoded bytes
//    PrivateKey privateKey = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(decodedPrivateKeyBytes));

    PrivateKey privateKey = loadPrivateKey("C:/Users/ahmed/.step/secrets/root_ca_key", "smallstep123");

    // Create JWT
    this.token = Jwts.builder()
      .setAudience(this.caUrl + "/1.0/sign")
      .claim("sha", this.caFingerprint)
      .setExpiration(Date.from(Instant.now().plus(5, ChronoUnit.MINUTES)))
      .setIssuedAt(Date.from(Instant.now()))
      .setNotBefore(Date.from(Instant.now()))
      .setId(UUID.randomUUID().toString())
      .setIssuer(this.provisionerName)
      .claim("sans", csr.getDnsSans())
      .setSubject(csr.getCn())
//      .signWith(Keys.hmacShaKeyFor(jwkParsed.getBytes()), SignatureAlgorithm.ES256)
      .signWith(privateKey, SignatureAlgorithm.ES256)
      .compact();
  }

  private PrivateKey loadPrivateKey(String privateKeyPath, String password) throws IOException, Exception {
    try (PEMParser pemParser = new PEMParser(new FileReader(privateKeyPath))) {
      Object object = pemParser.readObject();
      JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
      if (object instanceof PEMEncryptedKeyPair) {
        PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build(password.toCharArray());
        return converter.getKeyPair(((PEMEncryptedKeyPair) object).decryptKeyPair(decProv)).getPrivate();
      } else if (object instanceof PEMKeyPair) {
        return converter.getKeyPair((PEMKeyPair) object).getPrivate();
      } else {
        throw new IllegalArgumentException("Invalid key format");
      }
    }
  }

  public String getToken() {
    return token;
  }

//  private List<GeneralName> extractSubjectAlternativeNames(CSR csr) throws IOException {
//    List<GeneralName> sans = new ArrayList<>();
//    byte[] extensionBytes = csr.getEncoded();
//    ASN1Sequence seq = ASN1Sequence.getInstance(extensionBytes);
//    for (int i = 0; i < seq.size(); i++) {
//      ASN1TaggedObject tagged = (ASN1TaggedObject) seq.getObjectAt(i);
//      if (tagged.getTagNo() == 0) {
//        Extensions exts = Extensions.getInstance(tagged, false);
//        Extension sanExt = exts.getExtension(Extension.subjectAlternativeName);
//        if (sanExt != null) {
//          ASN1Encodable names = GeneralName.getInstance(
//            sanExt.getParsedValue()).getName();
//         sans.add((GeneralName) names);
//        }
//      }
//    }
//    return sans;
//  }
}
