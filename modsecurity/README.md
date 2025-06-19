JavaCPP Presets for ModSecurity
================================

[![Gitter](https://badges.gitter.im/bytedeco/javacpp.svg)](https://gitter.im/bytedeco/javacpp) [![Maven Central](https://maven-badges.herokuapp.com/maven-central/org.bytedeco/modsecurity/badge.svg)](https://maven-badges.herokuapp.com/maven-central/org.bytedeco/modsecurity) [![Sonatype Nexus (Snapshots)](https://img.shields.io/nexus/s/https/oss.sonatype.org/org.bytedeco/modsecurity.svg)](http://bytedeco.org/builds/)  
<sup>Build status for all platforms:</sup> [![modsecurity](https://github.com/bytedeco/javacpp-presets/workflows/modsecurity/badge.svg)](https://github.com/bytedeco/javacpp-presets/actions?query=workflow%3Amodsecurity)  <sup>Commercial support:</sup> [![xscode](https://img.shields.io/badge/Available%20on-xs%3Acode-blue?style=?style=plastic&logo=appveyor&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAMAAACdt4HsAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAAZQTFRF////////VXz1bAAAAAJ0Uk5T/wDltzBKAAAAlUlEQVR42uzXSwqAMAwE0Mn9L+3Ggtgkk35QwcnSJo9S+yGwM9DCooCbgn4YrJ4CIPUcQF7/XSBbx2TEz4sAZ2q1RAECBAiYBlCtvwN+KiYAlG7UDGj59MViT9hOwEqAhYCtAsUZvL6I6W8c2wcbd+LIWSCHSTeSAAECngN4xxIDSK9f4B9t377Wd7H5Nt7/Xz8eAgwAvesLRjYYPuUAAAAASUVORK5CYII=)](https://xscode.com/bytedeco/javacpp-presets)


Introduction
------------
This directory contains the JavaCPP Presets module for:

 * ModSecurity 3.0.8  https://github.com/SpiderLabs/ModSecurity

Please refer to the parent README.md file for more detailed information about the JavaCPP Presets.


Documentation
-------------
Java API documentation is available here:

 * http://bytedeco.org/javacpp-presets/modsecurity/apidocs/


Build Notes
------------

To build the JavaCPP Presets for ModSecurity, libraries required by ModSecurity should be installed.

### Prerequisites

#### macOS (including Apple Silicon)
Install required dependencies using Homebrew:
```bash
brew install autoconf automake libtool pcre
```

#### Linux
Install development packages:
```bash
# Ubuntu/Debian
sudo apt-get install autoconf automake libtool libpcre3-dev

# CentOS/RHEL
sudo yum install autoconf automake libtool pcre-devel
```

### Building from Source

To build the JavaCPP Presets for ModSecurity from source:

1. **Clone the repository:**
   ```bash
   git clone https://github.com/bytedeco/javacpp-presets.git
   cd javacpp-presets/modsecurity
   ```

2. **Build the native libraries and Java bindings:**
   ```bash
   mvn clean install
   ```

   This will:
   - Download and compile ModSecurity C++ library
   - Generate Java bindings using JavaCPP
   - Create platform-specific JAR files with native libraries

3. **Platform Support:**
   - Linux x86_64
   - macOS x86_64 (Intel)
   - **macOS arm64 (Apple Silicon)** ✅ *Newly supported*
   - Windows (requires additional setup)

### Manual Build Process

For manual building or troubleshooting:

```bash
# Clean previous builds
bash cppbuild.sh clean modsecurity

# Build native libraries
bash cppbuild.sh install modsecurity

# Build Java bindings
mvn clean compile
```

For detailed compilation information, refer to:
 * https://github.com/SpiderLabs/ModSecurity/wiki/Compilation-recipes-for-v3.x


Sample Usage
------------
Here is a simple example of ModSecurity ported to Java from this C++ source file:

 * https://github.com/SpiderLabs/ModSecurity#simple-example-using-c

We can use [Maven 3](http://maven.apache.org/) to download and install automatically all the class files as well as the native binaries.

### Running the Sample

After creating the `pom.xml` and `ModSecuritySimpleIntervention.java` source files below:
```bash
mvn compile exec:java
```

#### Expected Output
```
There is intervention !!!
MessageRuleSize 1
RuleMessage id = 1 message  =  ' Attack detected' t:lowercase
```

### The `pom.xml` build file
```xml
<project>
    <modelVersion>4.0.0</modelVersion>
    <groupId>org.bytedeco.modsecurity</groupId>
    <artifactId>samples</artifactId>
    <version>3.0.8-1.5.8</version>
    <properties>
        <exec.mainClass>ModSecuritySimpleIntervention</exec.mainClass>
        <maven.compiler.source>1.8</maven.compiler.source>
        <maven.compiler.target>1.8</maven.compiler.target>
    </properties>
    <dependencies>
        <dependency>
            <groupId>org.bytedeco</groupId>
            <artifactId>modsecurity-platform</artifactId>
            <version>3.0.8-1.5.8</version>
        </dependency>
    </dependencies>
    <build>
        <sourceDirectory>.</sourceDirectory>
    </build>
</project>
```

### The `ModSecuritySimpleIntervention.java` source file
```java
import java.util.Optional;
import org.bytedeco.javacpp.*;
import org.bytedeco.modsecurity.*;

public class ModSecuritySimpleIntervention {
    private static final String BASIC_RULE =
            "SecRuleEngine On\n" +
            "SecRule REQUEST_URI \"@streq /attack\" \"id:1,phase:1,msg: \' Attack detected\' t:lowercase,deny\"";

    public static void main(String[]args){
        ModSecurity modSecurity = new ModSecurity();

        RulesSet rulesSet = new RulesSet();
        rulesSet.load(BASIC_RULE);

        Transaction transaction = new Transaction(modSecurity, rulesSet, null);
        transaction.processConnection("127.0.0.1", 4455, "", 80);
        transaction.processURI("https://modsecurity.org/attack", "GET", "1.0");
        transaction.addResponseHeader("HTTP/1.1", "200 OK");
        transaction.processResponseHeaders(200, "HTTP/1.1");
        transaction.processRequestBody();
        transaction.processRequestHeaders();

        ModSecurityIntervention modSecurityIntervention = new ModSecurityIntervention();
        boolean isIntervention = transaction.intervention(modSecurityIntervention);

        if (isIntervention){
            System.out.println("There is intervention !!!");
            logRuleMessages(transaction.m_rulesMessages());
        }
    }

    private static void logRuleMessages(RuleMessageList messageList){
        if (messageList != null && !messageList.isNull() && !messageList.empty()) {
            long size = messageList.size();
            System.out.println("MessageRuleSize " +  size);
            RuleMessageList.Iterator iterator = messageList.begin();
            for (int i = 0; i < size; i++) {
                logRuleMessage(iterator.get());
                iterator.increment();
            }
        }
    }

    private static void logRuleMessage(RuleMessage ruleMessage){
        System.out.println("RuleMessage id = "+ ruleMessage.m_ruleId()+ " message  = " + Optional.ofNullable(ruleMessage.m_message()).map(BytePointer::getString).orElse("NO_MESSAGE"));
    }
}
```
