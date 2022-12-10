package com.learning.config;

import java.io.FileWriter;
import java.io.IOException;

public class SoftHSMConfigProvider implements HSMConfigProvider {

    @Override
    public void createConfigFile(String hsmConfigFilePath, String hsmSharedLibraryFile, String slot) throws IOException {
        FileWriter fw = new FileWriter(hsmConfigFilePath);

        fw.write("name = SoftHSM\n" + "library = " + hsmSharedLibraryFile);
        fw.write("\n slot = " + slot + "\n" + "attributes(generate, *, *) = {\n");
        fw.write("\t CKA_TOKEN = true\n}\n" + "attributes(generate, CKO_CERTIFICATE, *) = {\n");
        fw.write("\t CKA_PRIVATE = false\n}\n" + "attributes(generate, CKO_PUBLIC_KEY, *) = {\n");
        fw.write("\t CKA_PRIVATE = false\n}\n");
        fw.close();
    }
}
