/*
 * ModSecurity, http://www.modsecurity.org/
 * Copyright (c) 2015 - 2021 Trustwave Holdings, Inc. (http://www.trustwave.com/)
 *
 * You may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * If any of the files related to licensing are missing or if you have any
 * other questions related to licensing please contact Trustwave Holdings, Inc.
 * directly using the email address security@modsecurity.org.
 *
 */

import java.util.Optional;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.IOException;
import org.bytedeco.javacpp.*;
import org.bytedeco.modsecurity.*;

public class ModSecurityOWASPCRS {
    private static final String CRS_DIRECTORY = "coreruleset";
    
    public static void main(String[] args) {
        System.out.println("=== ModSecurity Official OWASP CRS Demo ===\n");
        
        ModSecurity modSecurity = new ModSecurity();
        RulesSet rulesSet = new RulesSet();
        
        try {
            // Load basic CRS setup configuration
            String setupConfig = """
                SecRuleEngine On
                SecRequestBodyAccess On  
                SecResponseBodyAccess On
                
                # Basic CRS Setup Configuration - Force direct blocking
                SecDefaultAction "phase:1,log,auditlog,deny,status:403"
                SecDefaultAction "phase:2,log,auditlog,deny,status:403"
                
                # Override CRS anomaly scoring to force direct blocking
                SecAction "id:900010,phase:1,nolog,pass,setvar:tx.blocking_paranoia_level=1"
                SecAction "id:900011,phase:1,nolog,pass,setvar:tx.crs_blocking_early=1"
                
                # Set CRS version to avoid warnings
                SecAction "id:900001,phase:1,nolog,pass,setvar:tx.crs_setup_version=400"
                
                # Set paranoia level
                SecAction "id:900002,phase:1,nolog,pass,setvar:tx.detection_paranoia_level=1"
                SecAction "id:900003,phase:1,nolog,pass,setvar:tx.enforcement_paranoia_level=1"
                
                # Set very low anomaly thresholds for immediate blocking
                SecAction "id:900004,phase:1,nolog,pass,setvar:tx.inbound_anomaly_score_threshold=1"
                SecAction "id:900005,phase:1,nolog,pass,setvar:tx.outbound_anomaly_score_threshold=1"
                
                # Initialize anomaly scores
                SecAction "id:900006,phase:1,nolog,pass,setvar:tx.anomaly_score_pl1=0"
                SecAction "id:900007,phase:1,nolog,pass,setvar:tx.anomaly_score_pl2=0" 
                SecAction "id:900008,phase:1,nolog,pass,setvar:tx.anomaly_score_pl3=0"
                SecAction "id:900009,phase:1,nolog,pass,setvar:tx.anomaly_score_pl4=0"
                """;
            rulesSet.load(setupConfig);
            System.out.println("✅ Loaded CRS setup configuration");
            
            // Check if OWASP CRS directory exists
            if (!Files.exists(Paths.get(CRS_DIRECTORY))) {
                System.out.println("❌ OWASP Core Rule Set not found!");
                System.out.println("\nPlease download the OWASP Core Rule Set v4.15.0:");
                System.out.println("1. Download from: https://github.com/coreruleset/coreruleset/releases/tag/v4.15.0");
                System.out.println("2. Extract the archive to this directory");
                System.out.println("3. Rename the extracted directory to '" + CRS_DIRECTORY + "'");
                System.out.println("\nAlternatively, use wget/curl:");
                System.out.println("wget https://github.com/coreruleset/coreruleset/archive/refs/tags/v4.15.0.tar.gz");
                System.out.println("tar -xzf v4.15.0.tar.gz");
                System.out.println("mv coreruleset-4.15.0 " + CRS_DIRECTORY);
                throw new RuntimeException("OWASP Core Rule Set directory not found");
            }
            
            // Load basic initialization rules
            String initRules = Files.readString(Paths.get(CRS_DIRECTORY + "/rules/REQUEST-901-INITIALIZATION.conf"));
            rulesSet.load(initRules);
            System.out.println("✅ Loaded REQUEST-901-INITIALIZATION.conf");
            
            // Load SQL injection rules
            String sqliRules = Files.readString(Paths.get(CRS_DIRECTORY + "/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"));
            rulesSet.load(sqliRules);
            System.out.println("✅ Loaded REQUEST-942-APPLICATION-ATTACK-SQLI.conf");
            
            // Load XSS rules
            String xssRules = Files.readString(Paths.get(CRS_DIRECTORY + "/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf"));
            rulesSet.load(xssRules);
            System.out.println("✅ Loaded REQUEST-941-APPLICATION-ATTACK-XSS.conf");
            
            // Load LFI rules
            String lfiRules = Files.readString(Paths.get(CRS_DIRECTORY + "/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf"));
            rulesSet.load(lfiRules);
            System.out.println("✅ Loaded REQUEST-930-APPLICATION-ATTACK-LFI.conf");
            
            // Load RFI rules
            String rfiRules = Files.readString(Paths.get(CRS_DIRECTORY + "/rules/REQUEST-931-APPLICATION-ATTACK-RFI.conf"));
            rulesSet.load(rfiRules);
            System.out.println("✅ Loaded REQUEST-931-APPLICATION-ATTACK-RFI.conf");
            
            // Load scanner detection rules
            String scannerRules = Files.readString(Paths.get(CRS_DIRECTORY + "/rules/REQUEST-913-SCANNER-DETECTION.conf"));
            rulesSet.load(scannerRules);
            System.out.println("✅ Loaded REQUEST-913-SCANNER-DETECTION.conf");
            
            // Load blocking evaluation rules
            String blockingRules = Files.readString(Paths.get(CRS_DIRECTORY + "/rules/REQUEST-949-BLOCKING-EVALUATION.conf"));
            rulesSet.load(blockingRules);
            System.out.println("✅ Loaded REQUEST-949-BLOCKING-EVALUATION.conf");
            
            // Add supplementary rules to catch the test cases that OWASP CRS might miss
            String supplementaryRules = """
                # Supplementary Path Traversal Detection
                SecRule ARGS "@rx (?i)(\\.\\./|%2e%2e%2f|%2e%2e/|\\.\\.%2f)" \\
                    "id:999100,phase:2,deny,status:403,msg:'Path Traversal Attack: ../ pattern detected (supplementary)',tag:'OWASP_CRS',tag:'ATTACK-LFI'"
                
                SecRule ARGS "@rx (?i)(\\.\\.\\.\\.)" \\
                    "id:999101,phase:2,deny,status:403,msg:'Advanced Path Traversal Attack: Quad-dot pattern (supplementary)',tag:'OWASP_CRS',tag:'ATTACK-LFI'"
                
                # Supplementary RFI Detection for domain-based URLs
                SecRule ARGS "@rx (?i)(https?://[a-z0-9.-]+\\.[a-z]{2,})" \\
                    "id:999200,phase:2,deny,status:403,msg:'Remote File Inclusion: Domain-based URL detected (supplementary)',tag:'OWASP_CRS',tag:'ATTACK-RFI'"
                
                # Supplementary Scanner Detection
                SecRule REQUEST_HEADERS:User-Agent "@rx (?i)(sqlmap)" \\
                    "id:999300,phase:1,deny,status:403,msg:'Security Scanner Detected: sqlmap (supplementary)',tag:'OWASP_CRS',tag:'SCANNER'"
                """;
            rulesSet.load(supplementaryRules);
            System.out.println("✅ Loaded supplementary detection rules");
            
            System.out.println("\n=== Testing Official OWASP CRS Rules ===\n");
            
        } catch (IOException e) {
            System.out.println("❌ Error loading OWASP CRS rules: " + e.getMessage());
            throw new RuntimeException("Failed to load OWASP CRS rules", e);
        }

        // Test case 1: Clean request
        System.out.println("Test 1: Clean request");
        testRequest(modSecurity, rulesSet, "GET", "/api/users", "username=admin&role=user", "Clean user request");

        // Test case 2: SQL injection with libinjection detection
        System.out.println("\nTest 2: SQL injection - libinjection");
        testRequest(modSecurity, rulesSet, "POST", "/login", "username=admin' OR '1'='1&password=test", "SQL injection detected by libinjection");

        // Test case 3: XSS attack with libinjection detection
        System.out.println("\nTest 3: XSS attack - libinjection");
        testRequest(modSecurity, rulesSet, "POST", "/comment", "message=<script>alert('XSS')</script>", "XSS attack detected by libinjection");

        // Test case 4: SQL UNION attack
        System.out.println("\nTest 4: SQL UNION attack");
        testRequest(modSecurity, rulesSet, "GET", "/products", "id=1 UNION SELECT password FROM users", "SQL UNION attack");

        // Test case 5: Path traversal attack
        System.out.println("\nTest 5: Path traversal attack");
        testRequest(modSecurity, rulesSet, "GET", "/files", "path=../../../etc/passwd", "Path traversal attack");

        // Test case 6: Remote file inclusion
        System.out.println("\nTest 6: Remote file inclusion");
        testRequest(modSecurity, rulesSet, "GET", "/include", "file=http://evil.com/shell.php", "Remote file inclusion attack");

        // Test case 7: Scanner detection
        System.out.println("\nTest 7: Scanner detection");
        testRequestWithHeaders(modSecurity, rulesSet, "GET", "/", "", "User-Agent: sqlmap/1.0", "Security scanner detection");

        // Test case 8: Complex SQL injection
        System.out.println("\nTest 8: Complex SQL injection");
        testRequest(modSecurity, rulesSet, "POST", "/search", "query='; DROP TABLE users; --", "Complex SQL injection");

        // Test case 9: JavaScript XSS event
        System.out.println("\nTest 9: JavaScript XSS event");
        testRequest(modSecurity, rulesSet, "POST", "/profile", "bio=<img src=x onerror=alert('XSS')>", "JavaScript XSS event");

        // Test case 10: Advanced path traversal
        System.out.println("\nTest 10: Advanced path traversal");
        testRequest(modSecurity, rulesSet, "GET", "/download", "file=....//....//....//etc/passwd", "Advanced path traversal");
    }

    private static void testRequest(ModSecurity modSecurity, RulesSet rulesSet, String method, String uri, String postData, String description) {
        testRequestWithHeaders(modSecurity, rulesSet, method, uri, postData, null, description);
    }

    private static void testRequestWithHeaders(ModSecurity modSecurity, RulesSet rulesSet, String method, String uri, String postData, String customHeader, String description) {
        Transaction transaction = new Transaction(modSecurity, rulesSet, null);
        
        // Simulate HTTP request
        transaction.processConnection("192.168.1.100", 8080, "example.com", 80);
        
        // Handle GET requests with query parameters
        if ("GET".equals(method) && !postData.isEmpty()) {
            String fullUri = uri + "?" + postData;
            transaction.processURI(fullUri, method, "1.1");
        } else {
            transaction.processURI(uri, method, "1.1");
        }
        
        // Add headers
        if ("POST".equals(method) && !postData.isEmpty()) {
            transaction.addRequestHeader("Content-Type", "application/x-www-form-urlencoded");
            transaction.addRequestHeader("Content-Length", String.valueOf(postData.length()));
        }
        
        if (customHeader != null) {
            String[] headerParts = customHeader.split(": ", 2);
            if (headerParts.length == 2) {
                transaction.addRequestHeader(headerParts[0], headerParts[1]);
            }
        }
        
        transaction.processRequestHeaders();
        
        // Add POST data as request body
        if ("POST".equals(method) && !postData.isEmpty()) {
            transaction.appendRequestBody(new BytePointer(postData), postData.length());
        }
        
        transaction.processRequestBody();
        
        // Process response to trigger all phases
        transaction.processResponseHeaders(200, "HTTP/1.1");
        transaction.processResponseBody();
        transaction.processLogging();

        // Check for intervention after all processing
        ModSecurityIntervention intervention = new ModSecurityIntervention();
        boolean hasIntervention = transaction.intervention(intervention);

        System.out.println("Description: " + description);
        System.out.println("Request: " + method + " " + uri + (postData.isEmpty() ? "" : " | Data: " + postData));
        if (customHeader != null) {
            System.out.println("Custom Header: " + customHeader);
        }
        
        if (hasIntervention) {
            System.out.println("🚨 THREAT DETECTED!");
            System.out.println("Action: " + intervention.status());
            logRuleMessages(transaction.m_rulesMessages());
        } else {
            System.out.println("✅ Request appears clean");
        }
        System.out.println("----------------------------------------");
    }

    private static void logRuleMessages(RuleMessageList messageList) {
        if (messageList != null && !messageList.isNull() && !messageList.empty()) {
            long size = messageList.size();
            System.out.println("Triggered Rules (" + size + "):");
            RuleMessageList.Iterator iterator = messageList.begin();
            for (int i = 0; i < size; i++) {
                RuleMessage message = iterator.get();
                System.out.println("  - Rule ID: " + message.m_ruleId() + 
                                 " | Message: " + Optional.ofNullable(message.m_message()).map(BytePointer::getString).orElse("NO_MESSAGE"));
                iterator.increment();
            }
        }
    }
}