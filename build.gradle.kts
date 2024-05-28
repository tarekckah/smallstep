plugins {
    id("java")
}

group = "org.example"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(platform("org.junit:junit-bom:5.10.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    implementation("org.apache.httpcomponents:httpclient:4.5.14")
    implementation("org.json:json:20090211")
    implementation("javax.xml.bind:jaxb-api:2.2.4")
//    implementation("org.bouncycastle:bcprov-jdk15on:1.70")
//    implementation("org.bouncycastle:bcpkix-jdk15on:1.78.1")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.78.1")
    implementation("com.google.code.gson:gson:2.7")
    implementation("io.jsonwebtoken:jjwt:0.12.5")
    implementation("net.sourceforge.argparse4j:argparse4j:0.9.0")
    implementation("com.nimbusds:nimbus-jose-jwt:9.39.1")
// https://mvnrepository.com/artifact/com.auth0/java-jwt
    implementation("com.auth0:java-jwt:4.4.0")

}

tasks.test {
    useJUnitPlatform()
}