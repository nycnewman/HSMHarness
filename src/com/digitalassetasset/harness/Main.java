package com.digitalassetasset.harness;

import javax.crypto.KeyAgreement;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.*;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;


public class Main {
    public static void main(String[] args) throws Exception {

        System.out.println("Digital Asset HSM JCE provider test harness");
        boolean displayProviderInfo = true;
        boolean displayAliases = true;
        boolean deleteExisting = true;

        final String algorithm = "EC";
        //final String algorithm = "RSA";

        //final String curveAlgorithm = "ed25519"; // "ed25519"
        //final String curveAlgorithm = "curve25519"; // "ed25519"
        //final String curveAlgorithm = "secp256k1"; // "secp256k1"
        final String curveAlgorithm = "secp256r1"; // "secp256r1"
        //final String curveAlgorithm = "secp521r1"; // "secp521r1"

        //final String signAlgorithm = "EdDSA"; // "EdDSA"
        final String signAlgorithm = "SHA256withECDSA"; //"SHA256withECDSA"
        //final String signAlgorithm = "SHA256withRSA";
        //final String signAlgorithm = "EC_DSA_SHA_2_256"; //"SHA256withECDSA"
        final String x509SignAlgorithm = "SHA256withECDSA"; //"SHA256withECDSA"
        //final String x509SignAlgorithm = "SHA256withRSA"; //"SHA256withECDSA"
        //final String x509SignAlgorithm = "EdDSA"; //"SHA256withECDSA"

        final String dhAlgorithm = "ECDH";
        //final String dhAlgorithm = "DH";

        int choice = 5;
        HSM hsm = null;
        switch (choice) {
            case 1:
                //hsm = new SecurosysHSMFactory().get();
                break;
            case 2:
                //hsm = new SunECHSMFactory().get();
                break;
            case 3:
                //hsm = new BouncyCastleHSMFactory().get();
                break;
            case 4:
                //hsm = new AWSCloudHSMFactory().get();
                break;
            case 5:
                hsm = new SunPKCS11Factory().get();
        }

        final String providerName = hsm.getProviderName();
        final String keyStoreTypeName = hsm.getKeyStoreTypeName();
        final Provider keyStoreProvider = hsm.getKeyStoreProvider();

        System.out.println("Curve Algorithm: " + curveAlgorithm);
        System.out.println("Sign Algorithm: " + signAlgorithm);
        System.out.println("X509 Sign Algorithm: " + x509SignAlgorithm);
        System.out.println("DH Algorithm: " + dhAlgorithm);
        System.out.println("Provider: " + providerName);
        System.out.println("keyStore type: " + keyStoreTypeName);

        char[] keyStorePasswordCharArray = "0002password1234".toCharArray();
        //char[] keyStorePasswordCharArray = "1111".toCharArray();
        String keyStoreName = "mytestkey.jks";

        hsm.login();

        if (displayProviderInfo) {
            try {
                Provider p[] = Security.getProviders();

                for (int i = 0; i < p.length; i++) {
                    System.out.println(p[i]);
                    for (Enumeration e = p[i].keys(); e.hasMoreElements(); )
                        System.out.println("\t" + e.nextElement());
                }
            } catch (Exception e) {
                System.out.println(e);
            }

            Provider[] providers = Security.getProviders();
            Set<String> ciphers = new HashSet<String>();
            Set<String> keyAgreements = new HashSet<String>();
            Set<String> macs = new HashSet<String>();
            Set<String> messageDigests = new HashSet<String>();
            Set<String> signatures = new HashSet<String>();
            Set<String> stores = new HashSet<String>();
            Set<String> factories = new HashSet<String>();

            for (int i = 0; i != providers.length; i++) {
                Iterator it = providers[i].keySet().iterator();

                while (it.hasNext()) {
                    String entry = (String) it.next();

                    if (entry.startsWith("Alg.Alias.")) {
                        entry = entry.substring("Alg.Alias.".length());
                    }

                    if (entry.startsWith("Cipher.")) {
                        ciphers.add(entry.substring("Cipher.".length()));
                    } else if (entry.startsWith("KeyAgreement.")) {
                        keyAgreements.add(entry.substring("KeyAgreement.".length()));
                    } else if (entry.startsWith("Mac.")) {
                        macs.add(entry.substring("Mac.".length()));
                    } else if (entry.startsWith("MessageDigest.")) {
                        messageDigests.add(entry.substring("MessageDigest.".length()));
                    } else if (entry.startsWith("Signature.")) {
                        signatures.add(entry.substring("Signature.".length()));
                    } else if (entry.startsWith("KeyStore.")) {
                        stores.add(entry.substring("KeyStore.".length()));
                    } else if (entry.startsWith("KeyFactory.")) {
                        factories.add(entry.substring("KeyFactory.".length()));
                    }
                }

                for (final Provider.Service service : providers[i].getServices()) {
                    System.out.println(service);
                }
            }

            printSet("Ciphers", ciphers);
            printSet("KeyAgreements", keyAgreements);
            printSet("Macs", macs);
            printSet("MessageDigests", messageDigests);
            printSet("Signatures", signatures);
            printSet("KeyStores", stores);
            printSet("KeyFactories", factories);
        }

        try { // guaranteed logout

            System.out.println("Testing: " + providerName + " " + keyStoreTypeName);
            System.out.println("Getting keystore details:");
            final KeyStore keyStore = KeyStore.getInstance(keyStoreTypeName, keyStoreProvider);
            if (keyStoreTypeName.equals("JCEKS") || keyStoreTypeName.equals("JKS")) {
                InputStream readStream = null;
                try {
                    readStream = new FileInputStream(keyStoreName);
                    keyStore.load(readStream, keyStorePasswordCharArray);
                } catch (Exception ex) {
                    System.out.println("No keys");
                    keyStore.load(null, keyStorePasswordCharArray); // no-op, but mandatory for JCA
                } finally {
                    if (readStream != null) {
                        readStream.close();
                    }
                }
            } else {
                keyStore.load(null, keyStorePasswordCharArray); // no-op, but mandatory for JCA
            }

            try {
                System.out.println("Size: " + keyStore.size());

                if (displayAliases) {
                    System.out.println("Current aliases:");
                    Enumeration<String> aliases = keyStore.aliases();
                    String alias = null;
                    while (aliases.hasMoreElements()) {
                        alias = aliases.nextElement().toString();
                        System.out.println(alias);
                        if (deleteExisting) {
                            System.out.println("Deleting entry: " + alias);
                            try {
                                keyStore.deleteEntry(alias);
                            }
                            catch (Exception e) {
                                System.out.println("ERROR: Key deletion not supported");
                                System.out.println(e);
                                e.printStackTrace();
                                System.exit(1);
                            }
                        }
                    }
                }
            } catch (Exception e) {
                System.out.println(e);
                e.printStackTrace();
                System.exit(1);
            }

            // generate bogus keypair(!) with named-curve params
            //KeyPairGenerator kpg9 = KeyPairGenerator.getInstance("EC", providerName);
            //ECGenParameterSpec gps = new ECGenParameterSpec ("secp256k1"); // NIST P-256
            //kpg9.initialize(gps);
            //KeyPair apair = kpg9.generateKeyPair();
            //ECPublicKey apub  = (ECPublicKey)apair.getPublic();
            //ECParameterSpec aspec = apub.getParams();

            // could serialize aspec for later use (in compatible JRE)
            //
            // for test only reuse bogus pubkey, for real substitute values
            //ECPoint apoint = apub.getW();
            //BigInteger x = apoint.getAffineX(), y = apoint.getAffineY();

            // construct point plus params to pubkey
            //ECPoint bpoint = new ECPoint (x,y);
            //ECPublicKeySpec bpubs = new ECPublicKeySpec (bpoint, aspec);
            //KeyFactory kfa = KeyFactory.getInstance ("EC", providerName);
            //ECPublicKey bpub = (ECPublicKey) kfa.generatePublic(bpubs);

            //
            // for test sign with original key, verify with reconstructed key
            //Signature sig = Signature.getInstance ("SHA256withECDSA");
            //byte [] data = "test".getBytes();
            //sig.initSign(apair.getPrivate());
            //sig.update (data);
            //byte[] dsig = sig.sign();
            //sig.initVerify(bpub);
            //sig.update(data);
            //System.out.println (sig.verify(dsig));

            //int x = 0, y = 0;
            //ECPoint pubPoint = new ECPoint(new BigInteger(1, x),new BigInteger(1, y));
            //AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC", "SunEC");
            //parameters.init(new ECGenParameterSpec("secp256r1"));
            //ECParameterSpec ecParameters = parameters.getParameterSpec(ECParameterSpec.class);
            //ECPublicKeySpec pubSpec = new ECPublicKeySpec(pubPoint, ecParameters);
            //KeyFactory kf = KeyFactory.getInstance("EC");
            //ECPublicKey pk = (ECPublicKey)kf.generatePublic(pubSpec);

            //SecureRandom
            SecureRandom secureRandom = SecureRandom.getInstance("PKCS11", keyStoreProvider);
            System.out.println("\n\n\nTesting Random Number Generator\nRandom Int: " + secureRandom.nextInt() + "\n\n\n");


            // Phase 1 of testing
            System.out.println("Phase 1");

            System.out.println("generating key pair");
            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm, keyStoreProvider);

            if (algorithm == "EC") {
                ECGenParameterSpec ecsp;
                ecsp = new ECGenParameterSpec(curveAlgorithm);
                keyPairGenerator.initialize(ecsp);
            }
            else {
                RSAKeyGenParameterSpec rsasp;
                rsasp = new RSAKeyGenParameterSpec(4096, RSAKeyGenParameterSpec.F4);
                keyPairGenerator.initialize(rsasp);
            }

            final KeyPair keyPair = keyPairGenerator.generateKeyPair();

            String keyName = UUID.randomUUID().toString(); // random name for persisted private key

            //System.out.println("public key: " + Arrays.toString(keyPair.getPublic().getEncoded()));

            java.security.cert.Certificate[] chain = null;
            if (!curveAlgorithm.equals("ed25519")) {
                chain = new X509Certificate[1];
                chain[0] = generateCertificate("CN=" + keyName, keyPair, 365, x509SignAlgorithm, keyStoreProvider);
            }
            else {
                //    chain = new Certificate[] {new PrimusCertificate(keyPair.getPublic())};
                chain = new java.security.cert.Certificate[]{null};
            }

            java.security.cert.Certificate cert = null;
            PublicKey pk = null;
            try {
                if (keyStoreTypeName.equals("JCEKS") || keyStoreTypeName.equals("JKS")) {

                    keyStore.setKeyEntry(keyName, keyPair.getPrivate(), keyStorePasswordCharArray, chain);
                    OutputStream writeStream = new FileOutputStream(keyStoreName);
                    keyStore.store(writeStream, keyStorePasswordCharArray);
                    writeStream.close();
                } else {

                    //keyStore.setKeyEntry(keyName, keyPair.getPrivate(), keyStorePasswordCharArray, new Certificate[]{null});
                    //keyStore.setKeyEntry(keyName, keyPair.getPrivate(), keyStorePasswordCharArray,new Certificate[] {new PrimusCertificate(keyPair.getPublic())});
                    //keyName = "my_key_alias";
                    keyStore.setKeyEntry(keyName, keyPair.getPrivate(), keyStorePasswordCharArray, chain);
                }

                System.out.println("fetching certificate [and public key]");
                cert = keyStore.getCertificate(keyName);
                System.out.println(cert);
                pk = null;
                if (cert != null) {
                    pk = cert.getPublicKey();
                    System.out.println(pk);
                }
            }
            catch (Exception e) {
                System.out.println("ERROR: Exception trying to store key");
                System.out.println(e.toString());
                e.printStackTrace();
                System.exit(1);
            }

            System.out.println("signing message");
            final byte[] message = UUID.randomUUID().toString().getBytes();
            final Signature signature = Signature.getInstance(signAlgorithm, keyStoreProvider);
            signature.initSign(keyPair.getPrivate());
            signature.update(message);
            final byte[] signatureBytes = signature.sign();

            System.out.println("verifying signature");
            final Signature verifySignature = Signature.getInstance(signAlgorithm, keyStoreProvider);
            verifySignature.initVerify(keyPair.getPublic());
            verifySignature.update(message);
            final boolean verified = verifySignature.verify(signatureBytes);

            System.out.println("verified: " + verified);

            // Phase 2 of testing
            System.out.println("Phase 2");

            System.out.println("generating ECC key pair");
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, keyStoreProvider);

            ECGenParameterSpec ecsp2;
            ecsp2 = new ECGenParameterSpec(curveAlgorithm);

            kpg.initialize(ecsp2);

            KeyPair kpU = kpg.genKeyPair();
            PrivateKey privKeyU = kpU.getPrivate();
            keyName = UUID.randomUUID().toString(); // random name for persisted private key

            //chain = new X509Certificate[1];
            //chain[0] = generateCertificate("CN="+keyName, keyPair, 365, x509SignAlgorithm, providerName);
            chain = null;
            if (!curveAlgorithm.equals("ed25519")) {
                chain = new X509Certificate[1];
                chain[0] = generateCertificate("CN=" + keyName, keyPair, 365, x509SignAlgorithm, keyStoreProvider);
            }
            else {
                //    chain = new Certificate[] {new PrimusCertificate(keyPair.getPublic())};
                chain = new java.security.cert.Certificate[]{null};
            }

            try {
                if (keyStoreTypeName.equals("JCEKS") || keyStoreTypeName.equals("JKS")) {

                    keyStore.setKeyEntry(keyName, privKeyU, keyStorePasswordCharArray, chain);
                    OutputStream writeStream = new FileOutputStream(keyStoreName);
                    keyStore.store(writeStream, keyStorePasswordCharArray);
                    writeStream.close();
                } else {
                    keyStore.setKeyEntry(keyName, privKeyU, keyStorePasswordCharArray, chain);
                }

                System.out.println("fetching certificate [and public key]");
                cert = keyStore.getCertificate(keyName);
                System.out.println(cert);
                if (cert != null) {
                    pk = cert.getPublicKey();
                    System.out.println(pk);
                }
            }
            catch (Exception e) {
                System.out.println("ERROR: Exception trying to store key");
                System.out.println(e.toString());
                e.printStackTrace();
                System.exit(1);
            }

            PublicKey pubKeyU = kpU.getPublic();
            System.out.println("User U: " + privKeyU.toString());
            System.out.println("User U: " + pubKeyU.toString());

            KeyPair kpV = kpg.genKeyPair();
            PrivateKey privKeyV = kpV.getPrivate();
            keyName = UUID.randomUUID().toString(); // random name for persisted private key

            //chain = new X509Certificate[1];
            //chain[0] = generateCertificate("CN="+keyName, keyPair, 365, signAlgorithm, providerName);
            chain = null;
            if (!curveAlgorithm.equals("ed25519")) {
                chain = new X509Certificate[1];
                chain[0] = generateCertificate("CN=" + keyName, keyPair, 365, x509SignAlgorithm, keyStoreProvider);
            }
            else {
                //    chain = new Certificate[] {new PrimusCertificate(keyPair.getPublic())};
                chain = new java.security.cert.Certificate[]{null};
            }

            try {
                if (keyStoreTypeName.equals("JCEKS") || keyStoreTypeName.equals("JKS")) {
                    keyStore.setKeyEntry(keyName, privKeyV, keyStorePasswordCharArray, chain);
                    OutputStream writeStream = new FileOutputStream(keyStoreName);
                    keyStore.store(writeStream, keyStorePasswordCharArray);
                    writeStream.close();
                } else {
                    keyStore.setKeyEntry(keyName, privKeyV, keyStorePasswordCharArray, chain);
                }

                System.out.println("fetching certificate [and public key]");
                cert = keyStore.getCertificate(keyName);
                System.out.println(cert);
                if (cert != null) {
                    pk = cert.getPublicKey();
                    System.out.println(pk);
                }
            }
            catch (Exception e) {
                System.out.println("ERROR: Exception trying to store key");
                System.out.println(e);
                e.printStackTrace();
                System.exit(1);
            }

            PublicKey pubKeyV = kpV.getPublic();
            System.out.println("User V: " + privKeyV.toString());
            System.out.println("User V: " + pubKeyV.toString());

            KeyAgreement ecdhU = KeyAgreement.getInstance(dhAlgorithm, keyStoreProvider);
            ecdhU.init(privKeyU);
            ecdhU.doPhase(pubKeyV, true);

            KeyAgreement ecdhV = KeyAgreement.getInstance(dhAlgorithm, keyStoreProvider);
            ecdhV.init(privKeyV);
            ecdhV.doPhase(pubKeyU, true);

            System.out.println("Secret computed by U: 0x" +
                    (new BigInteger(1, ecdhU.generateSecret()).toString(16)).toUpperCase());
            System.out.println("Secret computed by V: 0x" +
                    (new BigInteger(1, ecdhV.generateSecret()).toString(16)).toUpperCase());

            Signature ecdsa;
            ecdsa = Signature.getInstance(signAlgorithm, keyStoreProvider);
            ecdsa.initSign(privKeyU);

            String text = "In teaching others we teach ourselves";
            System.out.println("Text: " + text);
            byte[] baText = text.getBytes("UTF-8");

            ecdsa.update(baText);
            byte[] baSignature = ecdsa.sign();
            System.out.println("Signature: 0x" + (new BigInteger(1, baSignature).toString(16)).toUpperCase());

            Signature signature2;
            signature2 = Signature.getInstance(signAlgorithm, keyStoreProvider);
            signature2.initVerify(pubKeyU);
            signature2.update(baText);
            boolean result = signature2.verify(baSignature);
            System.out.println("Valid: " + result);


        } catch (Exception ex) {
            ex.printStackTrace();
        } finally {
            System.out.println("logging out");
            hsm.logout();
            System.exit(1);
        }

        System.out.println("Starting bulk test");
        hsm.login();

        try { // guaranteed logout

            // Phase 3 of testing
            // Timed testing of key generation and signing
            System.out.println("Phase 3");

            int totalCount = 100;

            long initDurationTotal = 0;
            long genDurationTotal = 0;
            long signDurationTotal = 0;
            long verifyDurationTotal = 0;
            long secretDurationTotal = 0;

            for (int i = 0; i < totalCount; i++) {

                System.out.println(i);
                long startTime = System.nanoTime();
                final KeyPairGenerator keyPairGenerator3 = KeyPairGenerator.getInstance(algorithm, keyStoreProvider);

                ECGenParameterSpec ecsp3;
                ecsp3 = new ECGenParameterSpec(curveAlgorithm);

                keyPairGenerator3.initialize(ecsp3);
                long keyInitTime = System.nanoTime();

                final KeyPair keyPair3 = keyPairGenerator3.generateKeyPair();
                long keyGenTime = System.nanoTime();

                //String keyName3 = UUID.randomUUID().toString(); // random name for persisted private key

                //Certificate[] chain3 = null;
                //chain3 = new X509Certificate[1];
                //chain3[0] = generateCertificate("CN=" + keyName3, keyPair3, 365, x509SignAlgorithm, providerName);

                //keyStore.setKeyEntry(keyName3, keyPair3.getPrivate(), keyStorePasswordCharArray, chain3);


                final byte[] message3 = UUID.randomUUID().toString().getBytes();
                final Signature signature3 = Signature.getInstance(signAlgorithm, keyStoreProvider);
                signature3.initSign(keyPair3.getPrivate());
                signature3.update(message3);
                final byte[] signatureBytes3 = signature3.sign();
                long signTime = System.nanoTime();

                final Signature verifySignature3 = Signature.getInstance(signAlgorithm, keyStoreProvider);
                verifySignature3.initVerify(keyPair3.getPublic());
                verifySignature3.update(message3);
                final boolean verified3 = verifySignature3.verify(signatureBytes3);
                long verifyTime = System.nanoTime();

                PrivateKey privKey3 = keyPair3.getPrivate();
                PublicKey pubKey3 = keyPair3.getPublic();

                KeyAgreement ecdh3 = KeyAgreement.getInstance(dhAlgorithm, keyStoreProvider);
                ecdh3.init(privKey3);
                ecdh3.doPhase(pubKey3, true);

                BigInteger secret = new BigInteger(1, ecdh3.generateSecret());

                long secretTime = System.nanoTime();

                long initDuration = (keyInitTime - startTime);  //divide by 1000000 to get milliseconds.
                long genDuration = (keyGenTime - keyInitTime);  //divide by 1000000 to get milliseconds.
                long signDuration = (signTime - keyGenTime);  //divide by 1000000 to get milliseconds.
                long verifyDuration = (verifyTime - signTime);  //divide by 1000000 to get milliseconds.
                long secretDuration = (secretTime - verifyTime);  //divide by 1000000 to get milliseconds.

                initDurationTotal += initDuration;
                genDurationTotal += genDuration;
                signDurationTotal += signDuration;
                verifyDurationTotal += verifyDuration;
                secretDurationTotal += secretDuration;

                //System.out.println("Durations: Init: " + (initDuration/1000000) + " Gen: " + (genDuration/1000000) + " Sign: " + (signDuration/1000000) + " Verify: " + (verifyDuration/1000000) + " Secret: " + (secretDuration/1000000) );
            }

            System.out.println("Average Durations: Init: " + (initDurationTotal/1000000/totalCount) + " Gen: " + (genDurationTotal/1000000/totalCount) + " Sign: " + (signDurationTotal/1000000/totalCount) + " Verify: " + (verifyDurationTotal/1000000/totalCount) + " Secret: " + (secretDurationTotal/1000000/totalCount) );

        } catch (Exception ex) {
            ex.printStackTrace();
        } finally {
            System.out.println("logging out");
            hsm.logout();
        }

        System.out.println("Test Harness done");
    }

    /**
     * Create a self-signed X.509 Example
     *
     * @param dn        the X.509 Distinguished Name, eg "CN=Test, L=London, C=GB"
     * @param pair      the KeyPair
     * @param days      how many days from now the Example is valid for
     * @param algorithm the signing algorithm, eg "SHA1withRSA"
     */
    public static X509Certificate generateCertificate(String dn, KeyPair pair, int days, String algorithm, Provider provider)
            throws Exception {
        PrivateKey privkey = pair.getPrivate();
        //X509CertInfo info = new X509CertInfo();
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + days * 86400000l);
        //CertificateValidity interval = new CertificateValidity(from, to);
        BigInteger sn = new BigInteger(64, new SecureRandom());
        X500Name owner = new X500Name(dn);
        X500Name issuer = new X500Name("CN=Digital Asset Issuer,O=Digital Asset,C=US");

        //info.set(X509CertInfo.VALIDITY, interval);
        //info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn));
        //info.set(X509CertInfo.SUBJECT, owner);
        //info.set(X509CertInfo.ISSUER, issuer);
        //info.set(X509CertInfo.KEY, new CertificateX509Key(pair.getPublic()));
        //info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
        //AlgorithmId algo = AlgorithmId.get(algorithm);;
        //info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));

        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(owner, sn, notBefore, notAfter,
                owner, SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded()));

        ContentSigner contentSigner = new JcaContentSignerBuilder(algorithm).build(pair.getPrivate());
        X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(builder.build(contentSigner));

        return certificate;
    }


    public static void printSet(String setName, Set algorithms) {
        System.out.println(setName + ":");
        if (algorithms.isEmpty()) {
            System.out.println("            None available.");
        } else {
            Iterator it = algorithms.iterator();
            while (it.hasNext()) {
                String name = (String) it.next();

                System.out.println("            " + name);
            }
        }
    }
}
