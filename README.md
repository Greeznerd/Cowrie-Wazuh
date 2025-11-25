# Cowrie-Wazuh
Cowrie and Wazuh oink oink

<!--
  COWRIE → WAZUH LOCAL RULESET (DOCUMENTATION COMMENT)
  ====================================================

  This section provides documentation for the custom Wazuh rules
  used to detect activity inside a Cowrie SSH/Telnet honeypot.
  It is intentionally commented out so it will NOT affect XML
  parsing or Wazuh functionality.

  HOW COWRIE LOGS REACH THE WAZUH MANAGER
  =======================================

  Cowrie generates JSON event logs here (on the Cowrie VM):
      /opt/cowrie/var/log/cowrie/cowrie.json

  The Wazuh agent on the Cowrie VM is configured to monitor
  this file by adding the following to:

      /var/ossec/etc/ossec.conf    [On the Cowrie honeypot VM 192.168.56.10]

      <localfile>
        <log_format>json</log_format>
        <location>/opt/cowrie/var/log/cowrie/cowrie.json</location>
      </localfile>

  This causes the Wazuh agent to forward all Cowrie JSON events
  to the Wazuh Manager (192.168.56.11), which then evaluates
  them against the custom rules defined below in:

      /var/ossec/etc/rules/local_rules.xml

  WHAT THESE RULES DETECT
  =======================

  • New SSH sessions to the honeypot
  • Closed SSH sessions
  • Any command entered in a Cowrie session
        (eventid: cowrie.command.input)

  • Dangerous / destructive commands:
        - rm -rf
        - chmod 777
        - chown root:root
        - ./binary execution

  • Persistence attempts:
        - crontab modifications

  • File download attempts:
        - wget
        - curl

  • Privilege escalation attempts:
        - sudo
        - su

  • Encoding / decoding behavior:
        - base64

  • Directory traversal (../../..)

  • Package installation:
        - apt-get
        - yum
        - dnf

  • Modification attempts on sensitive system files:
        - /etc/passwd
        - /etc/shadow

  ALERT LEVELS
  ============

    Level 6   = interesting / notable behavior
    Level 8   = suspicious activity
    Level 10+ = high/critical malicious behavior

  HOW TO USE THESE RULES
  ======================

  1. Add the rule definitions below this comment block.
  2. Save the file:
         /var/ossec/etc/rules/local_rules.xml
  3. Restart the Wazuh Manager:
         sudo systemctl restart wazuh-manager
         sudo systemctl status wazuh-manager
  4. Generate Cowrie activity from your attacker machine (Kali):
         whoami, pwd, rm -rf /tmp/test, crontab -l,
         wget http://example.com/x, base64 tests, etc.
  5. View alerts in Wazuh → Security Events:
         Use a DQL filter such as:

           rule.group:"cowrie"
           OR rule.id:910001 OR rule.id:910002 OR ...
           OR data.eventid:"cowrie.command.input"

  You should now see clear, descriptive alerts for all Cowrie
  sessions, commands, and malicious behaviors.

  END OF DOCUMENTATION — RULES BEGIN BELOW
  =======================================
--> Rules can be found in /local_rules.xml and fetched with command: "sudo curl -L -o /var/ossec/etc/rules/local_rules.xml https://raw.githubusercontent.com/Greeznerd/Cowrie-Wazuh/main/local_rules.xml"

