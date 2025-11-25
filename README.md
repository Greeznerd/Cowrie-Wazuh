# Cowrie-Wazuh

Cowrie → Wazuh Local Ruleset Documentation

This document explains how the custom Wazuh rules in this repository are used to detect activity inside a Cowrie SSH/Telnet honeypot. The content originally existed as an XML comment, but it belongs here in the README where it is easier to read and maintain.

How Cowrie Logs Reach the Wazuh Manager

Cowrie generates its JSON event logs on the Cowrie honeypot VM. These logs are written to the file located at /opt/cowrie/var/log/cowrie/cowrie.json.
The Wazuh agent installed on the Cowrie VM is configured to monitor this file and forward any new events to the Wazuh Manager.
This configuration is added inside /var/ossec/etc/ossec.conf on the Cowrie VM.
Once configured, the agent forwards Cowrie’s JSON log entries to the Wazuh Manager at 192.168.56.11.
The Wazuh Manager then evaluates the incoming log data using the custom rules defined on the manager in /var/ossec/etc/rules/local_rules.xml.

What the Rules Detect

The rules are designed to identify attacker behavior inside the Cowrie honeypot.
They react to new and closed SSH sessions, any commands typed inside Cowrie, and patterns that indicate potentially dangerous or malicious actions.
Examples include the execution of destructive commands like rm -rf, attempts to change permissions or ownership, execution of uploaded binaries, and typical persistence techniques involving crontab.
They also detect attempts to download files using tools like wget or curl, privilege escalation attempts using sudo or su, and the use of base64 encoding, which attackers often apply to disguise payloads.
The rules also cover directory traversal attempts and package installation commands such as apt-get, yum, or dnf.
In addition, modifications or attempts to access sensitive system files — such as /etc/passwd or /etc/shadow — are flagged as high-severity events.

Alert Levels

The rules use three general alert levels to help categorize the severity of detected behavior.
Level 6 is used for notable behavior that may be interesting to review.
Level 8 indicates suspicious behavior that may reflect attacker reconnaissance or preparation.
Level 10 and higher marks activity that is clearly malicious or represents a high-risk action.

How to Use the Rules

The rules themselves are placed inside the local_rules.xml file on the Wazuh Manager under /var/ossec/etc/rules/.
After editing or replacing the file, the Wazuh Manager must be restarted for the changes to take effect.
This is done using standard systemctl commands.
Once the manager is restarted, you can test the rules by connecting to the Cowrie honeypot from an attacker workstation such as Kali Linux and running commands inside the honeypot session.
When properly configured, these actions will appear as alerts inside the Wazuh dashboard under Security Events.
Filtering by the rule group “cowrie”, by individual rule IDs, or by the specific Cowrie event IDs will help you verify that the rules are loading and triggering correctly.

End of Documentation

The full XML ruleset can be found in the accompanying local_rules.xml file in this repository.

Rules can be found in /local_rules.xml and fetched with command: "sudo curl -L -o /var/ossec/etc/rules/local_rules.xml https://raw.githubusercontent.com/Greeznerd/Cowrie-Wazuh/main/local_rules.xml"

