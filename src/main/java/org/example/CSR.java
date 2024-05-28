package org.example;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.List;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.example.exception.OperatorCreationException;

public class CSR {

  private KeyPair key;
  private String cn;
  private List<String> dnsSans;
  private byte[] csrPemBytes;

  public CSR(String cn, List<String> dnsSans)
    throws NoSuchAlgorithmException, OperatorCreationException, IOException, InvalidAlgorithmParameterException,
    org.bouncycastle.operator.OperatorCreationException {
    Security.addProvider(new BouncyCastleProvider());
    this.key = generatePrivateKey();
    this.cn = cn;
    this.dnsSans = dnsSans;
    this.csrPemBytes = generateCSR();
  }

  private KeyPair generatePrivateKey() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
    keyGen.initialize(new ECGenParameterSpec("secp384r1"));
    return keyGen.generateKeyPair();
  }

  private byte[] generateCSR()
    throws NoSuchAlgorithmException, OperatorCreationException, IOException, org.bouncycastle.operator.OperatorCreationException {
    X500Name subject = new X500Name("CN=" + cn);
    ExtensionsGenerator extGen = new ExtensionsGenerator();

    List<GeneralName> sans = dnsSans.stream().map(name -> new GeneralName(GeneralName.dNSName, new DERIA5String(name))).toList();
    GeneralNames subjectAltName = new GeneralNames(sans.toArray(new GeneralName[0]));

    extGen.addExtension(Extension.subjectAlternativeName, false, subjectAltName);
    extGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
    extGen.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(new KeyPurposeId[]{KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth}));

    Extensions extensions = extGen.generate();

    ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(key.getPrivate());

    PKCS10CertificationRequest csr = new JcaPKCS10CertificationRequestBuilder(subject, key.getPublic())
      .addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions)
      .build(signer);

    return csr.getEncoded();
  }

  public byte[] getCSR() {
    return csrPemBytes;
  }

  public String getCn() { return cn; }

  public String getKeyPem(String passphrase) throws IOException, OperatorCreationException {
    ByteArrayOutputStream keyPemStream = new ByteArrayOutputStream();
    JcaPEMWriter pemWriter = new JcaPEMWriter(new OutputStreamWriter(keyPemStream));
    pemWriter.writeObject(key, new JcePEMEncryptorBuilder("AES-256-CBC").build(passphrase.toCharArray()));
    pemWriter.close();
    return keyPemStream.toString();
  }

  public List<String> getDnsSans() {
    return dnsSans;
  }

  public KeyPair getKey() {
    return key;
  }
}