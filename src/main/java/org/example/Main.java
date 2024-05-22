package org.example;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.List;
import javax.xml.stream.events.Namespace;
import net.sourceforge.argparse4j.ArgumentParsers;
import net.sourceforge.argparse4j.inf.ArgumentParser;
import net.sourceforge.argparse4j.inf.ArgumentParserException;
import org.example.exception.OperatorCreationException;

public class Main {
  public static void main(String[] args)
    throws InvalidAlgorithmParameterException, org.bouncycastle.operator.OperatorCreationException, ArgumentParserException {
    ArgumentParser parser = ArgumentParsers.newFor("CSR Signing").build()
      .description("Get a CSR signed with a step-ca server.");
    parser.addArgument("ca_url").type(String.class).help("The step-ca URL");
    parser.addArgument("ca_fingerprint").type(String.class).help("The CA fingerprint");
    parser.addArgument("provisioner_name").type(String.class).help("The CA JWK provisioner to use");
    parser.addArgument("jwk_filename").type(String.class).help("The JWK private key filename (JSON formatted)");

    try {
      Namespace ns = (Namespace) parser.parseArgs(args);
      String jwk = new String(Files.readAllBytes(Paths.get(ns.toString())));
      StepClient stepClient = new StepClient(ns.toString(), ns.toString());

      // Example uses
      CSR csr = new CSR("example.com", List.of("example.com", "mysite.example.com"));
      CAToken caToken = new CAToken(stepClient.getUrl(), stepClient.getFingerprint(), csr,
        ns.toString(), jwk);
      X509Certificate certificate = stepClient.sign(csr.toString(), caToken.toString());
      byte[] certificatePemBytes = certificate.getEncoded();
      byte[] certificateDerBytes = certificate.getEncoded();
      PrivateKey privateKey = csr.getKey().getPrivate();
      String encryptedPrivateKeyPem = csr.getKeyPem("mysecretpw");
      System.out.println(new String(certificatePemBytes));
    } catch (IOException | NoSuchAlgorithmException | OperatorCreationException | InvalidKeySpecException e) {
      e.printStackTrace();
    } catch (CertificateEncodingException e) {
      throw new RuntimeException(e);
    }
  }
}