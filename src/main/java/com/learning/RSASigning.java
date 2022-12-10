package com.learning;

import com.learning.config.SoftHSMConfigProvider;
import com.learning.provider.PKCS11SunSecurityProvider;
import com.learning.provider.SecurityProvider;

import java.io.IOException;
import java.security.Provider;

public class RSASigning {

    private static SecurityProvider securityProvider;

    static {
        String configFilePath = "/tmp/softhsm.cfg";
        String hsmSharedLibFilePath = "/opt/homebrew/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so";

        securityProvider = new PKCS11SunSecurityProvider(new SoftHSMConfigProvider(), configFilePath, hsmSharedLibFilePath, "1632003794");
    }

    public static void main(String[] args) throws IOException {
        Provider pkcs11Provider = securityProvider.getInstance();
        
    }
}