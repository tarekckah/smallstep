package org.example;

import java.io.ByteArrayInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.xml.bind.DatatypeConverter;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.util.EntityUtils;
import org.json.JSONObject;

public class StepClient {

  private String url;
  private String fingerprint;
  private String rootPem;
  private String certBundleFn;

  public StepClient(String caUrl, String caFingerprint) {
    this.url = caUrl;
    this.fingerprint = caFingerprint;
    this.rootPem = this.root();
    this.certBundleFn = this.saveTempFile(this.rootPem);
  }

  private String root() {
    // Disable TLS verification warnings for this request.
    System.setProperty("org.apache.commons.logging.Log", "org.apache.commons.logging.impl.SimpleLog");
    System.setProperty("org.apache.commons.logging.simplelog.defaultlog", "error");

    try (CloseableHttpClient httpClient = HttpClients.custom()
      .setSSLContext(SSLContexts.custom().loadTrustMaterial(null, new TrustSelfSignedStrategy()).build())
      .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
      .build();) {
      HttpGet httpGet = new HttpGet(URI.create(url + "/root/" + fingerprint));
      HttpResponse response = httpClient.execute(httpGet);
      String responseBody = EntityUtils.toString(response.getEntity());
      JSONObject jsonObject = new JSONObject(responseBody);
      String rootPem = jsonObject.getString("ca");
      compareFingerprints(rootPem, fingerprint);
      return rootPem;
    } catch (Exception e) {
      e.printStackTrace();
      return null;
    } finally {
      // Re-enable TLS verification warnings
      System.setProperty("org.apache.commons.logging.simplelog.defaultlog", "info");
    }
  }

  public X509Certificate sign(String csr, String token) {
    try {
      TrustManager[] trustAllCerts = new TrustManager[]{
        new X509TrustManager() {
          public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
          }

          public void checkClientTrusted(X509Certificate[] certs, String authType) {
          }

          public void checkServerTrusted(X509Certificate[] certs, String authType) {
          }
        }
      };

      SSLContext sslContext = SSLContext.getInstance("SSL");
      sslContext.init(null, trustAllCerts, new java.security.SecureRandom());

      CloseableHttpClient httpClient = HttpClients.custom()
        .setSSLContext(sslContext)
        .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
        .build();

      HttpPost httpPost = new HttpPost(URI.create(url + "/1.0/sign"));
      JSONObject json = new JSONObject();
      json.put("csr", csr);
      json.put("ott", token);
      StringEntity entity = new StringEntity(json.toString());
      httpPost.setEntity(entity);
      httpPost.setHeader("Content-type", "application/json");

      HttpResponse response = httpClient.execute(httpPost);
      String responseBody = EntityUtils.toString(response.getEntity());
      JSONObject jsonObject = new JSONObject(responseBody);
      String crt = jsonObject.getString("crt");
      return loadPemX509Certificate(crt);
    } catch (Exception e) {
      e.printStackTrace();
      return null;
    }
  }

  private X509Certificate loadPemX509Certificate(String pem) throws Exception {
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    ByteArrayInputStream inputStream = new ByteArrayInputStream(pem.getBytes());
    return (X509Certificate) certificateFactory.generateCertificate(inputStream);
  }

  public void health() {
    try (CloseableHttpClient httpClient = HttpClients.custom().disableCookieManagement().build()) {
      HttpGet httpGet = new HttpGet(URI.create(url + "/health"));
      HttpResponse response = httpClient.execute(httpGet);
      String responseBody = EntityUtils.toString(response.getEntity());
      System.out.println(responseBody);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  private String saveTempFile(String contents) {
    try {
      Path tempFilePath = Files.createTempFile(null, null);
      String fileName = tempFilePath.toAbsolutePath().toString();
      FileWriter fileWriter = new FileWriter(fileName);
      fileWriter.write(contents);
      fileWriter.close();
      Runtime.getRuntime().addShutdownHook(new Thread(() -> {
        try {
          Files.deleteIfExists(Paths.get(fileName));
        } catch (IOException e) {
          e.printStackTrace();
        }
      }));
      return fileName;
    } catch (IOException e) {
      e.printStackTrace();
      return null;
    }
  }

  private void compareFingerprints(String pem, String fingerprint) throws NoSuchAlgorithmException, CertificateException {
    byte[] fingerprintBytes = DatatypeConverter.parseHexBinary(fingerprint);
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(pem.getBytes());
    X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(byteArrayInputStream);
    byte[] certFingerprintBytes = MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
    if (!Arrays.equals(fingerprintBytes, certFingerprintBytes)) {
      throw new CertificateException("WARNING: fingerprints do not match");
    }
  }

  public String getUrl() {
    return url;
  }

  public String getFingerprint() {
    return fingerprint;
  }

  private static class TrustAllCertificates implements X509TrustManager {
    public X509Certificate[] getAcceptedIssuers() {
      return null;
    }

    public void checkClientTrusted(X509Certificate[] certs, String authType) {
    }

    public void checkServerTrusted(X509Certificate[] certs, String authType) {
    }
  }
}
