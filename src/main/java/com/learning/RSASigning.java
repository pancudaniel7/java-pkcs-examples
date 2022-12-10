package com.learning;

import com.learning.config.HSMConfigProvider;
import com.learning.config.SoftHSMConfigProvider;

import java.security.KeyStore;
import java.security.KeyStoreException;

public class RSASigning {

    private static HSMConfigProvider hsmConfigProvider;

    static {
        hsmConfigProvider = new SoftHSMConfigProvider();
    }

    public static void main(String[] args) throws KeyStoreException {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");

    }
}
