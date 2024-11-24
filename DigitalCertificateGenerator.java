import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.PKCS12SafeBag;
import org.bouncycastle.pkcs.PKCS12PfxPduBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS12SafeBagBuilder;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

public class DigitalCertificateGenerator {
    public static void main(String[] args) {
        try {
            // Adiciona o BouncyCastle como provedor de segurança
            Security.addProvider(new BouncyCastleProvider());

            // Gera um par de chaves (privada e pública)
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // Informações do certificado
            X500Name issuer = new X500Name("CN=Certificado Digital, O=Minha Empresa, C=BR");
            X500Name subject = issuer; // Certificado autoassinado
            BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
            Date notBefore = new Date();
            Date notAfter = new Date(System.currentTimeMillis() + (365 * 24 * 60 * 60 * 1000L)); // 1 ano de validade

            // Cria o certificado X.509
            JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                    issuer, serialNumber, notBefore, notAfter, subject, keyPair.getPublic()
            );

            // Assina o certificado
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
            X509CertificateHolder certHolder = certBuilder.build(signer);
            X509Certificate certificate = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);

            // Cria o arquivo PFX
            char[] password = "senhaSegura123".toCharArray();
            JcaPKCS12SafeBagBuilder keyBagBuilder = new JcaPKCS12SafeBagBuilder(keyPair.getPrivate(), password);
            JcaPKCS12SafeBagBuilder certBagBuilder = new JcaPKCS12SafeBagBuilder(certificate);

            PKCS12SafeBag keyBag = keyBagBuilder.build();
            PKCS12SafeBag certBag = certBagBuilder.build();

            PKCS12PfxPduBuilder pfxBuilder = new PKCS12PfxPduBuilder();
            pfxBuilder.addData(keyBag);
            pfxBuilder.addData(certBag);

            byte[] pfxBytes = pfxBuilder.build(new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate())).getEncoded();

            // Salva o arquivo PFX
            try (FileOutputStream fos = new FileOutputStream("certificado.pfx")) {
                fos.write(pfxBytes);
            }

            System.out.println("Certificado PFX gerado com sucesso!");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
