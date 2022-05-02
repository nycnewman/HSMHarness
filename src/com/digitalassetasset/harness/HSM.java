package com.digitalassetasset.harness;

import java.security.Provider;

public interface HSM {
    public String getProviderName();
    public String getKeyStoreTypeName();
    public Provider getKeyStoreProvider();
    public void login();
    public void logout();
}
