package com.learning.provider;

import com.learning.config.HSMConfigProvider;

import java.io.IOException;
import java.security.Provider;
import java.security.Security;

public class PKCS11SunSecurityProvider implements SecurityProvider {

    private HSMConfigProvider hsmConfigProvider;
    private String configFilePath;
    private String hsmSharedLibFilePath;
    private final String slot;

    public PKCS11SunSecurityProvider(HSMConfigProvider hsmConfigProvider, String configFilePath, String hsmSharedLibFilePath, String slot) {
        this.hsmConfigProvider = hsmConfigProvider;
        this.configFilePath = configFilePath;
        this.hsmSharedLibFilePath = hsmSharedLibFilePath;
        this.slot = slot;
    }

    @Override
    public Provider getInstance() throws IOException {
        hsmConfigProvider.createConfigFile(configFilePath, hsmSharedLibFilePath, this.slot);
        Provider pkcs11Provider = Security.getProvider("SunPKCS11");
        pkcs11Provider = pkcs11Provider.configure(this.configFilePath);

        if (-1 == Security.addProvider(pkcs11Provider)) {
            throw new RuntimeException("could not add security provider");
        } else {
            System.out.println("provider initialized...");
        }

        Security.addProvider(pkcs11Provider);

        return pkcs11Provider;
    }
}
