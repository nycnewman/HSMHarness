package com.digitalassetasset.harness;

import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;

public class SunPKCS11 implements HSM {
    Provider provider;

    SunPKCS11()
    {
        System.out.println("installing the PKCS11 HSM JCE provider");
        String configName = "./pkcs11-yubicohsm.cfg";
        //String name = "YubiHSM";
        //String library = "/Users/edwardnewman/src/HSMTestHarness/lib/yubihsm_pkcs11.dylib";
        //String slotListIndex = "0";
        //String pkcs11Config = "name=" + name + "\nlibrary=" + library + "\n" + "showInfo=true\n" +
        //        "attributes(*, CKO_PRIVATE_KEY, CKK_RSA) = {\n" +
        //        "  CKA_SIGN=true\n" +
        //        "}" ;
        //java.io.ByteArrayInputStream pkcs11ConfigStream = new java.io.ByteArrayInputStream(pkcs11Config.getBytes());
        Provider newProvider = Security.getProvider("SunPKCS11");
        newProvider = newProvider.configure(configName);
        Security.addProvider(newProvider);
        this.provider = newProvider;
    }
    @Override
    public String getProviderName() {
        return "SunPKCS11";
    }

    @Override
    public Provider getKeyStoreProvider() {
        return this.provider;
    }

    @Override
    public String getKeyStoreTypeName() {
        return "PKCS11";
    }

    @Override
    public void login() {

        //String id = Integer.toHexString(15494);
        //String password = "k9fo5lsotks7";
        String id = Integer.toHexString(0002);
        String password = "password1234";
        char[] pin = (id + password).toCharArray();

        // Load the KeyStore using the pin
        try {
            KeyStore ks = KeyStore.getInstance("PKCS11", provider);
            ks.load(null, pin);
        } catch (Exception err) {
            System.out.println(err);
        }
    }

    @Override
    public void logout() {

    }
}
