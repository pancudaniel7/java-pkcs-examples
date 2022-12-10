package com.learning.config;

import java.io.IOException;

public interface HSMConfigProvider {
    void createConfigFile(String hsmConfigFilePath, String hsmSharedLibraryFile, String slot) throws IOException;
}
