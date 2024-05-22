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
    implementation("org.apache.httpcomponents:httpclient:4.5")
    implementation("org.json:json:20090211")
    implementation("javax.xml.bind:jaxb-api:2.2.4")
    implementation("org.bouncycastle:bcprov-jdk15on:1.70")
    implementation("org.bouncycastle:bcpkix-jdk15on:1.56")
    implementation("com.google.code.gson:gson:2.7")
    implementation("io.jsonwebtoken:jjwt:0.12.5")
    implementation("net.sourceforge.argparse4j:argparse4j:0.9.0")
}

tasks.test {
    useJUnitPlatform()
}