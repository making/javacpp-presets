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
import org.bytedeco.javacpp.*;
import org.bytedeco.modsecurity.*;

public class ModSecuritySQLInjectionDetection {
    private static final String SQL_INJECTION_RULES = """
            SecRuleEngine On
            SecRule ARGS "@detectSQLi" "id:1001,phase:2,deny,status:403,msg:'SQL Injection Attack Detected',logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}',tag:'application-multi',tag:'language-multi',tag:'platform-multi',tag:'attack-sqli',tag:'OWASP_CRS/WEB_ATTACK/SQL_INJECTION',tag:'WASCTC/WASC-19',tag:'OWASP_TOP_10/A1',tag:'PCI/6.5.2'"
            SecRule ARGS "@contains union" "id:1002,phase:2,deny,status:403,msg:'SQL Injection Attack: UNION keyword detected',logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}',tag:'application-multi',tag:'language-multi',tag:'platform-multi',tag:'attack-sqli'"
            SecRule ARGS "@rx (?i:select.*from)" "id:1003,phase:2,deny,status:403,msg:'SQL Injection Attack: SELECT FROM statement detected',logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}',tag:'application-multi',tag:'language-multi',tag:'platform-multi',tag:'attack-sqli'"
            SecRule ARGS "@rx (?i:(?:(?:['\\\"`](?:[^'\\\"`]|['\\\"`]{2})*['\\\"`]\\\\s*)*(?:;|\\\\||&&|\\\\|\\\\||&)*\\\\s*(?:(?:(['\\\"`]).*?\\\\1)|(?:[^\\\\s'\\\"`]*)))*\\\\s*?(?:(?:union(?:\\\\s+all)?\\\\s*\\\\(\\\\s*)?select))" "id:1004,phase:2,deny,status:403,msg:'SQL Injection Attack: Complex UNION SELECT detected',logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}',tag:'application-multi',tag:'language-multi',tag:'platform-multi',tag:'attack-sqli'"
            """;

    public static void main(String[] args) {
        System.out.println("=== ModSecurity SQL Injection Detection Demo ===\n");
        
        ModSecurity modSecurity = new ModSecurity();
        RulesSet rulesSet = new RulesSet();
        rulesSet.load(SQL_INJECTION_RULES);

        // Test case 1: Clean request
        System.out.println("Test 1: Clean request");
        testRequest(modSecurity, rulesSet, "user=admin&password=secret", "Clean user login");

        // Test case 2: Basic SQL injection
        System.out.println("\nTest 2: Basic SQL injection");
        testRequest(modSecurity, rulesSet, "user=admin' OR '1'='1&password=anything", "Basic SQL injection with OR condition");

        // Test case 3: UNION-based SQL injection
        System.out.println("\nTest 3: UNION-based SQL injection");
        testRequest(modSecurity, rulesSet, "id=1 UNION SELECT username,password FROM users", "UNION-based SQL injection");

        // Test case 4: Complex SQL injection
        System.out.println("\nTest 4: Complex SQL injection");
        testRequest(modSecurity, rulesSet, "search='; DROP TABLE users; --", "Table dropping attempt");

        // Test case 5: SELECT FROM injection
        System.out.println("\nTest 5: SELECT FROM injection");
        testRequest(modSecurity, rulesSet, "query=abc'; SELECT * FROM information_schema.tables WHERE '1'='1", "Information schema enumeration");
    }

    private static void testRequest(ModSecurity modSecurity, RulesSet rulesSet, String postData, String description) {
        Transaction transaction = new Transaction(modSecurity, rulesSet, null);
        
        // Simulate HTTP POST request
        transaction.processConnection("192.168.1.100", 8080, "example.com", 80);
        transaction.processURI("/login", "POST", "1.1");
        transaction.addRequestHeader("Content-Type", "application/x-www-form-urlencoded");
        transaction.addRequestHeader("Content-Length", String.valueOf(postData.length()));
        transaction.processRequestHeaders();
        
        // Add POST data as request body
        transaction.appendRequestBody(new BytePointer(postData), postData.length());
        transaction.processRequestBody();
        
        // Process response to trigger all phases
        transaction.processResponseHeaders(200, "HTTP/1.1");
        transaction.processResponseBody();
        transaction.processLogging();

        // Check for intervention after all processing
        ModSecurityIntervention intervention = new ModSecurityIntervention();
        boolean hasIntervention = transaction.intervention(intervention);

        System.out.println("Description: " + description);
        System.out.println("POST Data: " + postData);
        
        if (hasIntervention) {
            System.out.println("🚨 SQL Injection DETECTED!");
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