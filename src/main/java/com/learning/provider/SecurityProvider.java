package com.learning.provider;

import java.io.IOException;
import java.security.Provider;

public interface SecurityProvider {
    Provider getInstance() throws IOException;
}
