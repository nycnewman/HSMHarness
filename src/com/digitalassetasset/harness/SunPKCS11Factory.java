package com.digitalassetasset.harness;

public class SunPKCS11Factory implements AbstractHSMFactory {
    @Override
    public HSM get() {
        HSM hsm = new SunPKCS11();
        return hsm;
    }
}