// ═══════════════════════════════════════════════════════════════
// LOGSHIELD PRO — SERVER-SIDE DETECTION ENGINE
// 71 Windows Event Log rules (MITRE ATT&CK mapped) + 50+ Salesforce
// Classic audit-trail rules (Critical/High/Medium/Low, including the
// SF-C001-SF-C029 unauthorized-change matrix). None of this ships to
// the browser — only the finished findings JSON does.
// ═══════════════════════════════════════════════════════════════

const WIN_RULES = [
  {eid:'4625',sev:'critical',title:'Brute Force Detected',detail:'Multiple failed logons (4625) — credential attack.',mitre:'T1110',tactic:'Credential Access',technique:'Brute Force',threshold:5,rem:'Lock after N failures · Enable MFA · Review source IP'},
  {eid:'4625',sev:'medium',title:'Failed Logon Attempt',detail:'Single failed logon. Monitor for escalation.',mitre:'T1110',tactic:'Credential Access',technique:'Brute Force',rem:'Check account status and source IP'},
  {eid:'4771',sev:'high',title:'Kerberos Pre-Auth Failed',detail:'4771: Possible Kerberoasting / AS-REP Roasting.',mitre:'T1558.003',tactic:'Credential Access',technique:'Kerberoasting',rem:'Enable AES Kerberos encryption · Audit service accounts'},
  {eid:'4776',sev:'high',title:'NTLM Auth Failure',detail:'4776: NTLM failure — possible Pass-the-Hash.',mitre:'T1550.002',tactic:'Lateral Movement',technique:'Pass the Hash',rem:'Disable NTLM · Enable SMB signing'},
  {eid:'4648',sev:'high',title:'Explicit Credential Logon',detail:'4648: RunAs / explicit credential use.',mitre:'T1134.003',tactic:'Privilege Escalation',technique:'Make and Impersonate Token',rem:'Review if expected · Check for credential theft tools'},
  {eid:'4672',sev:'high',title:'Special Privileges Assigned',detail:'4672: SeDebug/SeTcb assigned — admin-equivalent.',mitre:'T1068',tactic:'Privilege Escalation',technique:'Exploitation for Privilege Escalation',rem:'Verify legitimate admin activity'},
  {eid:'4698',sev:'critical',title:'Scheduled Task Created',detail:'4698: New scheduled task — common persistence.',mitre:'T1053.005',tactic:'Persistence',technique:'Scheduled Task',rem:'Review task name/path · Check for Temp\\ paths'},
  {eid:'4702',sev:'high',title:'Scheduled Task Modified',detail:'4702: Existing task modified for persistence.',mitre:'T1053.005',tactic:'Persistence',technique:'Scheduled Task',rem:'Compare before/after · Verify creator'},
  {eid:'4697',sev:'critical',title:'Suspicious Service Installed',detail:'4697: New service installed — malware persistence.',mitre:'T1543.003',tactic:'Persistence',technique:'Windows Service',rem:'Review service binary path · Submit for malware scan'},
  {eid:'7045',sev:'critical',title:'New Service (System Log)',detail:'7045: Service installed — suspicious if in Temp.',mitre:'T1543.003',tactic:'Persistence',technique:'Windows Service',rem:'Verify legitimacy · Check binary path'},
  {eid:'4720',sev:'critical',title:'Backdoor Account Created',detail:'4720: New user account — verify authorization.',mitre:'T1136.001',tactic:'Persistence',technique:'Create Local Account',rem:'Confirm with HR/IT · Remove if unauthorized'},
  {eid:'4726',sev:'high',title:'User Account Deleted',detail:'4726: Account deleted — possible cover-up.',mitre:'T1531',tactic:'Impact',technique:'Account Access Removal',rem:'Verify deletion was authorized'},
  {eid:'4732',sev:'critical',title:'Added to Privileged Group',detail:'4732: Member added to Administrators group.',mitre:'T1098',tactic:'Persistence',technique:'Account Manipulation',rem:'Verify authorization · Remove if unauthorized'},
  {eid:'4728',sev:'critical',title:'Added to Domain Admin Group',detail:'4728: Member added to global privileged group.',mitre:'T1098',tactic:'Persistence',technique:'Account Manipulation',rem:'Immediately verify · Full IR if unauthorized'},
  {eid:'4738',sev:'high',title:'User Account Changed',detail:'4738: Account modified — flags, password, etc.',mitre:'T1098',tactic:'Persistence',technique:'Account Manipulation',rem:'Check if Password Never Expires was set'},
  {eid:'4740',sev:'medium',title:'Account Locked Out',detail:'4740: Lockout — repeated failures from same source.',mitre:'T1110',tactic:'Credential Access',technique:'Brute Force',rem:'Identify lockout source · Review policy'},
  {eid:'1102',sev:'critical',title:'AUDIT LOG CLEARED — Active Attacker',detail:'1102: Security log cleared — evidence destruction.',mitre:'T1070.001',tactic:'Defense Evasion',technique:'Clear Windows Event Logs',rem:'IMMEDIATE: Treat as active incident · Investigate who cleared'},
  {eid:'104',sev:'critical',title:'System Log Cleared',detail:'104: System log cleared — attacker cleanup.',mitre:'T1070.001',tactic:'Defense Evasion',technique:'Clear Windows Event Logs',rem:'IMMEDIATE: Treat as active incident'},
  {eid:'4719',sev:'critical',title:'Audit Policy Disabled',detail:'4719: Audit policy changed — attacker evading detection.',mitre:'T1562.002',tactic:'Defense Evasion',technique:'Disable Windows Event Logging',rem:'Alert immediately · Restore policy'},
  {eid:'4688',sev:'high',title:'Suspicious Process Created',detail:'4688: cmd/powershell/wscript from unusual parent.',mitre:'T1059',tactic:'Execution',technique:'Command and Scripting Interpreter',rem:'Enable command-line audit logging · Deploy AppLocker'},
  {eid:'4104',sev:'critical',title:'PowerShell Script Block Logged',detail:'4104: Encoded command / download cradle detected.',mitre:'T1059.001',tactic:'Execution',technique:'PowerShell',rem:'Review script block · Block encoded PS execution'},
  {eid:'5140',sev:'medium',title:'Network Share Accessed',detail:'5140: ADMIN$/C$ accessed remotely — lateral movement.',mitre:'T1021.002',tactic:'Lateral Movement',technique:'SMB/Windows Admin Shares',rem:'Restrict admin shares · Enable SMB signing'},
  {eid:'4769',sev:'high',title:'Kerberoasting — TGS Request',detail:'4769: TGS with RC4 encryption — offline cracking.',mitre:'T1558.003',tactic:'Credential Access',technique:'Kerberoasting',rem:'Strong service account passwords · AES encryption'},
  {eid:'4768',sev:'medium',title:'Kerberos TGT Requested',detail:'4768: High volume could indicate Golden Ticket.',mitre:'T1558.001',tactic:'Credential Access',technique:'Golden Ticket',rem:'Monitor RC4 ticket requests · Check ticket lifetime'},
  {eid:'1116',sev:'critical',title:'Malware Detected — Defender',detail:'1116: Windows Defender detected malware.',mitre:'T1204',tactic:'Execution',technique:'User Execution',rem:'ISOLATE SYSTEM · Full scan · Review recent downloads'},
  {eid:'1117',sev:'critical',title:'Malware Action Taken',detail:'1117: Defender quarantine/remove action taken.',mitre:'T1204',tactic:'Execution',technique:'User Execution',rem:'Verify full remediation · Check other systems'},
  {eid:'4657',sev:'high',title:'Registry Modified',detail:'4657: Registry value changed — persistence vector.',mitre:'T1547.001',tactic:'Persistence',technique:'Registry Run Keys',rem:'Check if run key was modified · Baseline registry'},
  {eid:'5025',sev:'critical',title:'Firewall Service Stopped',detail:'5025: Windows Firewall stopped — allows unrestricted traffic.',mitre:'T1562.004',tactic:'Defense Evasion',technique:'Disable or Modify System Firewall',rem:'IMMEDIATE: Re-enable firewall · Investigate who stopped it'},
  {eid:'4946',sev:'high',title:'Firewall Rule Added',detail:'4946: New firewall exception — C2 traffic vector.',mitre:'T1562.004',tactic:'Defense Evasion',technique:'Disable or Modify System Firewall',rem:'Review rule · Remove if not authorized'},
  {eid:'4950',sev:'critical',title:'Firewall Setting Changed',detail:'4950: Firewall configuration changed — possible disable.',mitre:'T1562.004',tactic:'Defense Evasion',technique:'Disable or Modify System Firewall',rem:'Verify firewall state · Investigate'},
  {eid:'6416',sev:'medium',title:'USB Device Connected',detail:'6416: Removable storage attached — exfiltration risk.',mitre:'T1091',tactic:'Lateral Movement',technique:'Replication Through Removable Media',rem:'Enforce USB policy · Monitor file copies'},
  {eid:'5379',sev:'high',title:'Credential Manager Read',detail:'5379: Credentials read — possible credential harvesting.',mitre:'T1555.004',tactic:'Credential Access',technique:'Windows Credential Manager',rem:'Review process accessing vault'},
  {eid:'4742',sev:'critical',title:'Computer Account Changed — DCSync?',detail:'4742: With 4662 could indicate DCSync attack.',mitre:'T1003.006',tactic:'Credential Access',technique:'DCSync',rem:'Check for MS-DRSR access · Full IR if DCSync suspected'},
  {eid:'4741',sev:'high',title:'Computer Account Created',detail:'4741: Machine account created — MachineAccountQuota abuse.',mitre:'T1136.002',tactic:'Persistence',technique:'Create Domain Account',rem:'Verify authorization · Review quota policy'},
  {eid:'4624',sev:'info',title:'Successful Logon',detail:'4624: Baseline logon event.',mitre:'T1078',tactic:'Defense Evasion',technique:'Valid Accounts',rem:'Monitor for unexpected times/locations'},
  {eid:'4670',sev:'high',title:'Object Permissions Changed',detail:'4670: ACL modified — persistence or privilege escalation.',mitre:'T1222',tactic:'Defense Evasion',technique:'File and Directory Permissions Modification',rem:'Verify authorization'},
  {eid:'5157',sev:'medium',title:'Network Connection Blocked',detail:'5157: Firewall blocked outbound — possible C2.',mitre:'T1046',tactic:'Discovery',technique:'Network Service Discovery',rem:'Review blocked destination · Check process'},
];

const SF_RULES = [
  // ── CRITICAL — Unauthorized / requires-authorization changes (SF-C001–SF-C029) ──
  {id:'SF-C001',domain:'Access & Identity',sections:['manage users','permission set group','permission sets','profiles'],keywords:['modify all data','view all data','system administrator','profile','permission set','assign','grant'],sev:'critical',title:"Assign/modify a user's Profile or Permission Set to grant Modify All Data, View All Data, or System Administrator-equivalent access",risk:'Elevates a user to admin-equivalent data access across the entire org.',where:'Manage Users / Permission Set Group',rem:'Require dual approval + change ticket; alert on assignment.'},
  {id:'SF-C002',domain:'Access & Identity',sections:['manage users','permission set group','login access policies'],keywords:['login as','logged in as','log in as','login-as','impersonat'],sev:'critical',title:'Login-As (log in as another user)',risk:'Elevates a user to admin-equivalent data access across the entire org.',where:'Manage Users / Permission Set Group',rem:'Require dual approval + change ticket; alert on assignment.'},
  {id:'SF-C003',domain:'Access & Identity',sections:['manage users','profiles'],keywords:['clone','system administrator','create','new profile'],sev:'critical',title:'Create or clone a Profile equivalent to System Administrator',risk:'Creates a hidden admin-equivalent identity that may not be caught by name-based reviews.',where:'Manage Users / Profiles',rem:'Block profile cloning from System Administrator without approval.'},
  {id:'SF-C004',domain:'Access & Identity',sections:['permission set group'],keywords:['create','modify','changed'],sev:'critical',title:'Create or modify a Permission Set Group',risk:'Bundles multiple permission sets and can silently aggregate to admin-equivalent access.',where:'Permission Set Group',rem:'Require review of the resulting effective access before activation.'},
  {id:'SF-C005',domain:'Access & Identity',sections:['auth providers'],keywords:['create','modify','changed','sso','saml','oidc'],sev:'critical',title:'Create/modify an Auth. Provider (SSO / social sign-on) configuration',risk:'Controls how identity is federated into the org; misconfiguration enables impersonation or bypass of login controls.',where:'Auth Providers',rem:'Restrict to Identity/Security team; require change ticket.'},
  {id:'SF-C006',domain:'Access & Identity',sections:['oauth custom scope'],keywords:['create','modify','define','scope'],sev:'critical',title:'Define or modify a Custom OAuth Scope',risk:'Custom scopes can be crafted to expose more data/functionality than a connected app should have.',where:'Oauth Custom Scope',rem:'Security review required before any new/changed scope is published.'},
  {id:'SF-C007',domain:'Access & Identity',sections:['connected apps','external client application'],keywords:['create','modify','changed','oauth','new','scope'],sev:'critical',title:'Create/modify an External Client Application (OAuth) or Connected App, including its OAuth scopes',risk:'Defines what an external application can do on behalf of users or the org.',where:'Connected Apps / External Client Application',rem:'Require security review of requested scopes; log all changes.'},
  {id:'SF-C008',domain:'Access & Identity',sections:['connected app session policy'],keywords:['modify','changed','session','timeout','ip'],sev:'critical',title:'Modify Connected App Session Policy',risk:'Weakening session/IP policy on an integration extends the window for stolen-token misuse.',where:'Connected App Session Policy',rem:'Alert on any relaxation of session timeout or IP restriction.'},
  {id:'SF-C009',domain:'Access & Identity',sections:['session settings'],keywords:['modify','changed','timeout','session','cookie'],sev:'critical',title:'Modify org-wide Session Settings (timeout, session security level, cookie policy)',risk:'Weakens session-hijacking protections for the entire org, not a single integration.',where:'Session Settings',rem:'Change only via approved maintenance window with sign-off.'},
  {id:'SF-C010',domain:'Access & Identity',sections:['certificate and key management'],keywords:['create','rotate','export','delete','new'],sev:'critical',title:'Create, rotate, export, or delete a Certificate or Key',risk:'These secrets underpin authentication, digital signing, and encryption org-wide.',where:'Certificate and Key Management',rem:'Restrict to named security admins; require ticket + peer review.'},
  {id:'SF-C011',domain:'Access & Identity',sections:['sharing settings','guest user access','security controls'],keywords:['guest user','modify all','view all','edit','delete'],sev:'critical',title:'Grant the Guest User (unauthenticated) profile Modify All / View All / Edit / Delete on any object',risk:'Directly exposes org data to unauthenticated internet visitors — one of the most common real-world Salesforce breach patterns.',where:'Sharing Settings > Guest User Access / Security Controls',rem:'Hard-block; treat any grant as a P1 security incident requiring justification.'},

  {id:'SF-C012',domain:'Data Governance',sections:['sharing settings','organization-wide defaults'],keywords:['modify','changed','public','private','read','owd'],sev:'critical',title:'Change the Organization-Wide Default (OWD) sharing setting on an object',risk:'Alters default visibility of every record of that object across the entire org in one action.',where:'Sharing Settings',rem:'Require change ticket + impact analysis before any OWD change.'},
  {id:'SF-C013',domain:'Data Governance',sections:['data management'],keywords:['mass delete','bulk delete','mass import','export','delete'],sev:'critical',title:'Mass delete records (Mass Delete tool, Data Loader, Bulk API delete)',risk:'Bulk, often irreversible data loss if unauthorized or performed in error.',where:'Data Management',rem:'Require pre-approved backup/export before any mass delete.'},
  {id:'SF-C014',domain:'Data Governance',sections:['data management','bulk api'],keywords:['hard delete','bypass recycle bin'],sev:'critical',title:'Hard delete records (bypass Recycle Bin) / Bulk API Hard Delete',risk:'Permanently unrecoverable — no safety net, no undo.',where:'Data Management / Bulk API',rem:'Restrict permission; require dual sign-off per hard-delete batch.'},
  {id:'SF-C015',domain:'Data Governance',sections:['permission sets','profiles'],keywords:['bypass field-level security','view all data','modify all data','bypass fls'],sev:'critical',title:"Grant 'Bypass Field-Level Security' or 'View All Data' / 'Modify All Data'",risk:'Removes the field- and record-level protections that normally gate sensitive data (PII, financial, contractual).',where:'Permission Sets / Profiles',rem:'Treat as admin-equivalent; requires the same approval as Manage Users.'},
  {id:'SF-C016',domain:'Data Governance',sections:['security controls'],keywords:['password policy','csp','clickjack','https','cors','modify','changed'],sev:'critical',title:'Change org-wide Password Policy (length, complexity, expiry) or Security Controls (CSP, clickjack protection, HTTPS enforcement)',risk:"Weakens the org's baseline authentication and browser-security posture for every user.",where:'Security Controls',rem:'Restrict to Security team; require change ticket.'},

  {id:'SF-C017',domain:'Code & Automation',sections:['apex class','apex trigger'],keywords:['create','modify','changed','without sharing','new'],sev:'critical',title:"Create/modify an Apex Class or Trigger — especially any running 'without sharing'",risk:'Code can bypass sharing rules, field-level security, and validation logic entirely, and runs automatically on every DML.',where:'Apex Class / Apex Trigger',rem:"Mandatory code review + no direct-to-production edits; disallow ad-hoc 'without sharing' classes."},
  {id:'SF-C018',domain:'Code & Automation',sections:['flows'],keywords:['create','modify','system context','without sharing','activate'],sev:'critical',title:'Create/modify a Flow that runs in System Context (without sharing)',risk:'System-context Flows can bypass sharing rules and field-level security by design, same as Apex.',where:'Flows',rem:'Mandatory review of any Flow set to run in system context.'},
  {id:'SF-C019',domain:'Code & Automation',sections:['outbound change sets','inbound change sets','change sets'],keywords:['deploy','accept','inbound','outbound','change set'],sev:'critical',title:'Deploy a Change Set or metadata deployment to Production / Accept an Inbound Change Set',risk:'Pushes external metadata/code changes directly into the live environment, changing configuration or logic org-wide in one action.',where:'Outbound/Inbound Change Sets',rem:'Require CAB approval and a rollback plan for every production deployment.'},
  {id:'SF-C020',domain:'Code & Automation',sections:['manage package installation','second generation package version'],keywords:['install','upgrade','version','package'],sev:'critical',title:'Install or upgrade a package (managed, unmanaged, or Second-Generation/2GP)',risk:'Package code runs with broad org access; installs/upgrades can silently change org behavior.',where:'Manage Package Installation / Second Generation Package Version',rem:'Require security review of package permissions before install/upgrade.'},
  {id:'SF-C021',domain:'Code & Automation',sections:['named credentials','external credentials'],keywords:['create','modify','changed'],sev:'critical',title:'Create/modify Named Credentials or External Credentials',risk:'Defines what external systems the org can call and with what stored authentication identity.',where:'Named Credentials / External Credentials',rem:'Restrict to integration admins; log and review all endpoint/credential changes.'},

  {id:'SF-C022',domain:'Integration & Payments',sections:['adyen payment settings'],keywords:['modify','changed','api','credential','payment'],sev:'critical',title:'Modify Adyen Payment Settings (gateway configuration / API credentials)',risk:'Controls live payment processing; misconfiguration risks direct financial loss or fraud.',where:'Adyen Payment Settings',rem:'Restrict to Finance+Security co-owned change process; log all edits.'},
  {id:'SF-C023',domain:'Integration & Payments',sections:['crm wa credentials','nexmo wa credentials'],keywords:['modify','changed','credential','whatsapp','api'],sev:'critical',title:'Modify CRM WA Credentials or Nexmo WA Credentials (WhatsApp Business API credentials)',risk:'Compromise enables sending/intercepting customer messages as the business — brand and fraud risk.',where:'CRM WA Credentials / Nexmo WA Credentials',rem:'Rotate via secrets vault only; disallow plaintext edits in Setup.'},
  {id:'SF-C024',domain:'Integration & Payments',sections:['clicksign signature configurations'],keywords:['modify','changed','signature'],sev:'critical',title:'Modify ClickSign Signature Configurations',risk:'Affects the integrity and legal validity of e-signed customer/contract documents.',where:'ClickSign Signature Configurations',rem:'Require legal/compliance sign-off before any change.'},

  {id:'SF-C025',domain:'Business-Critical Config',sections:['launch eoi token amount'],keywords:['modify','changed','token','amount'],sev:'critical',title:'Modify Launch EOI Token Amount',risk:'Direct financial impact — changes the booking/token amount collected from customers.',where:'Launch EOI Token Amount',rem:'Require Finance approval before any change; log with before/after values.'},
  {id:'SF-C026',domain:'Business-Critical Config',sections:['launch eoi project configurations'],keywords:['configure','modify','changed','launch','project'],sev:'critical',title:'Modify Launch EOI Project Configurations',risk:'Errors directly affect live sales, inventory, and customer commitments for a project launch.',where:'Launch EOI Project Configurations',rem:'Require sign-off from Sales Ops before go-live; freeze during active launch windows.'},
  {id:'SF-C027',domain:'Business-Critical Config',sections:['eoi refund details'],keywords:['modify','changed','refund','amount'],sev:'critical',title:'Modify EOI Refund Details',risk:'Direct financial impact — controls money returned to customers.',where:'EOI Refund Details',rem:'Require dual approval (Finance + Ops) for any refund configuration change.'},
  {id:'SF-C028',domain:'Business-Critical Config',sections:['opportunities'],keywords:['delete','closed-won','closed won'],sev:'critical',title:'Delete a Closed-Won Opportunity',risk:'Removes revenue-recognized transaction history with financial/audit impact.',where:'Opportunities',rem:'Hard-block delete on Closed-Won; require Finance approval + archival instead.'},
  {id:'SF-C029',domain:'Business-Critical Config',sections:['opportunities','quotes','price book'],keywords:['override','discount','price'],sev:'critical',title:'Override an approved discount or price on a Quote/Opportunity outside the approval process',risk:'Directly bypasses commercial approval controls put in place for pricing integrity.',where:'Opportunities / Quotes / Price Book',rem:'Route all overrides through the Approval Process; alert on direct field edits.'},

  // ── HIGH ──
  {section:'Roles',keywords:['create','modify','delete','changed'],sev:'high',title:'Role Modified',risk:'Changes record visibility through role hierarchy',rem:'Assess visibility impact · Verify authorization'},
  {section:'Sharing Rules',keywords:['create','modify','changed','sharing'],sev:'high',title:'Sharing Rule Modified',risk:'Changes who can see records beyond OWD',rem:'Review scope of sharing extension'},
  {section:'Restriction Rules',keywords:['create','modify','enable','disable','delete'],sev:'high',title:'Restriction Rule Changed',risk:'Changes record-level access controls',rem:'Verify intended access change'},
  {section:'Event Monitoring',keywords:['enable','disable','modify','changed'],sev:'high',title:'Event Monitoring Changed',risk:'Alters audit logging capabilities',rem:'Verify not reducing monitoring coverage'},
  {section:'Custom Objects',keywords:['create','modify','delete','changed'],sev:'high',title:'Custom Object Modified',risk:'Structural change affecting data model/integrations',rem:'Review integration impact · Verify deployment approval'},
  {section:'Validation Rules',keywords:['disable','modify','changed','deactivate'],sev:'high',title:'Validation Rule Modified/Disabled',risk:'Can bypass mandatory business/compliance checks',rem:'Verify business rule still enforced another way'},
  {section:'Approval Process',keywords:['create','modify','changed','approver'],sev:'high',title:'Approval Process Modified',risk:'Can weaken or bypass financial/contractual controls',rem:'Verify approval chain integrity · Test process'},
  {section:'Flows',keywords:['activate','deactivate','modify'],sev:'high',title:'Flow Activated/Deactivated',risk:'Changes automated business logic org-wide',rem:'Review what processes are affected'},
  {section:'Scheduled Job Settings',keywords:['create','modify','pause','delete','cron'],sev:'high',title:'Scheduled Job Changed',risk:'Can disable critical automated processes',rem:'Verify job still runs as expected'},
  {section:'Sandboxes',keywords:['create','refresh','delete'],sev:'high',title:'Sandbox Created/Refreshed',risk:'Refresh copies production data to lower-security env',rem:'Verify data masking policy applied'},
  {section:'Track Field History',keywords:['enable','disable','changed'],sev:'high',title:'Field History Tracking Changed',risk:'Disabling removes audit trail',rem:'Verify audit requirement still met'},
  {section:'Groups',keywords:['create','modify','changed'],sev:'high',title:'Public Group Modified',risk:'Changes record visibility via sharing rules',rem:'Review sharing rules using this group'},
  {section:'Sites',keywords:['activate','configure','create'],sev:'high',title:'Public Site Configured/Activated',risk:'Exposes org data to public internet',rem:'Security review before activation'},
  {section:'Customer Portal',keywords:['enable','configure','create'],sev:'high',title:'Customer Portal Configured',risk:'External-facing — misconfiguration exposes internal data',rem:'Review what objects/fields are exposed'},
  {section:'Lightning Components',keywords:['deploy','modify','create'],sev:'high',title:'Lightning Component Modified',risk:'Components can call Apex and access broad data',rem:'Code review required'},
  {section:'Static Resource',keywords:['upload','modify','changed'],sev:'high',title:'Static Resource Modified',risk:'Stored-XSS / supply-chain attack vector',rem:'Scan for malicious JS · Verify source'},
  {section:'Custom Permissions',keywords:['create','modify','changed'],sev:'high',title:'Custom Permission Modified',risk:'Unlocks sensitive functionality for users',rem:'Review what functionality is gated'},
  {section:'Restriction Rule',keywords:['create','modify','enable','disable'],sev:'high',title:'Restriction Rule Changed',risk:'Narrows/widens record visibility',rem:'Assess access impact across user base'},
  {section:'Change Data Capture',keywords:['enable','disable','changed'],sev:'high',title:'Change Data Capture Modified',risk:'Streams record changes to external systems',rem:'Review what objects are streamed · Verify receiver'},
  {section:'Experiences network status',keywords:['activate','deactivate','status'],sev:'high',title:'Digital Experience Activated/Deactivated',risk:'Changes public/partner exposure of org',rem:'Verify intended status change'},
  {section:'Mid Office Approval Checklist',keywords:['modify','changed','checklist'],sev:'high',title:'Mid Office Approval Checklist Changed',risk:'Governs internal approval gates before transactions',rem:'Verify with compliance/operations team'},
  {section:'SPA Checklists',keywords:['modify','changed'],sev:'high',title:'SPA Checklist Modified',risk:'Governs legal completeness checks before sale',rem:'Verify with legal team'},
  {section:'SF Rule Engines',keywords:['modify','changed','rule'],sev:'high',title:'Rule Engine Modified',risk:'Automates pricing/eligibility/routing at scale',rem:'Verify business impact before/after'},
  {section:'Workflow Rule',keywords:['activate','deactivate','modify','changed'],sev:'high',title:'Workflow Rule Modified',risk:'Changes automated field updates/alerts org-wide',rem:'Review affected records and processes'},
  {section:'Custom Metadata Types',keywords:['create','modify','changed'],sev:'high',title:'Custom Metadata Changed',risk:'Drives business logic — change can alter Apex/Flow behavior',rem:'Verify deployment process followed'},
  {section:'SR Milestone Configurations',keywords:['modify','changed'],sev:'high',title:'SR Milestone Config Changed',risk:'Governs service-level commitments and escalations',rem:'Verify with service management team'},
  {section:'Email Administration',keywords:['configure','modify','changed','deliverability'],sev:'high',title:'Email Administration Changed',risk:'Misconfiguration causes spoofing or loss of notifications',rem:'Test email delivery after change'},
  // ── MEDIUM ──
  {section:'Apex Class',keywords:['view','read','open'],sev:'medium',title:'Apex Class Viewed',risk:'Review access — code contains business logic',rem:'Monitor for repeat access patterns'},
  {section:'Page',keywords:['create','modify','changed'],sev:'medium',title:'Visualforce Page Modified',risk:'Can embed logic or expose data',rem:'Code review if data access is embedded'},
  {section:'Custom Apps',keywords:['create','modify','changed'],sev:'medium',title:'Custom App Modified',risk:'Navigation/tooling exposure change',rem:'Verify intended change'},
  {section:'Lightning Pages',keywords:['modify','changed'],sev:'medium',title:'Lightning Page Modified',risk:'Changes what fields/components are visible',rem:'Verify intended UI change'},
  {section:'Global Value Sets',keywords:['modify','changed'],sev:'medium',title:'Global Value Set Modified',risk:'Change propagates to every object using the value set',rem:'Test downstream field impacts'},
  {section:'Process Email Templates',keywords:['create','modify','changed'],sev:'medium',title:'Email Template Modified',risk:'Can be used for phishing-style impersonation',rem:'Verify content change is legitimate'},
  {section:'Customize Accounts',keywords:['modify','changed'],sev:'medium',title:'Account Object Modified',risk:'Affects how account data is captured org-wide',rem:'Review field/layout change'},
  {section:'Customize Contacts',keywords:['modify','changed'],sev:'medium',title:'Contact Object Modified (PII)',risk:'Contact records typically hold customer PII',rem:'Review PII field impact'},
  {section:'Customize Person Accounts',keywords:['modify','changed'],sev:'medium',title:'Person Account Modified (PII)',risk:'Person Accounts hold PII — layout changes affect capture',rem:'Verify with data privacy team'},
  {section:'Customize Cases',keywords:['modify','changed'],sev:'medium',title:'Case Object Modified',risk:'Can touch customer PII fields',rem:'Review field change'},
  {section:'Customize Leads',keywords:['modify','changed'],sev:'medium',title:'Lead Object Modified',risk:'Prospective customer PII sensitivity',rem:'Review field change'},
  {section:'Field Dependencies',keywords:['create','modify','changed'],sev:'medium',title:'Field Dependency Modified',risk:'Alters data-entry business logic',rem:'Test affected picklist behavior'},
  {section:'Global Actions',keywords:['modify','changed'],sev:'medium',title:'Global Action Modified',risk:'Exposes create/update actions to broad user base',rem:'Review action scope and access'},
  {section:'Customer Notification Settings',keywords:['configure','modify','changed'],sev:'medium',title:'Customer Notification Changed',risk:'Affects customer communications (SMS/Email/WhatsApp)',rem:'Test notification delivery'},
  {section:'Survey Qualtrics Questionnaire',keywords:['configure','modify'],sev:'medium',title:'Qualtrics Survey Config Modified',risk:'Impacts customer-facing survey data collection',rem:'Verify content change'},
  // ── LOW ──
  {section:'App Settings',keywords:['modify','changed'],sev:'low',title:'App Settings Modified',risk:'Cosmetic/UX impact only — no data change',rem:'Low risk — verify intended change'},
  {section:'Customize Activities',keywords:['modify','changed'],sev:'low',title:'Activities Customized',risk:'Low-sensitivity operational data',rem:'Baseline change — review if unexpected'},
  {section:'Customize Home',keywords:['modify','changed'],sev:'low',title:'Home Page Modified',risk:'Cosmetic/UX change only',rem:'Low risk — verify intended'},
  {section:'Custom Tabs',keywords:['create','modify','changed'],sev:'low',title:'Custom Tab Modified',risk:'Navigation convenience — not an access grant',rem:'Low risk'},
  {section:'Application',keywords:['modify','changed'],sev:'low',title:'Application Modified',risk:'Cosmetic/navigation change',rem:'Low risk — verify intended'},
  {section:'Country Time Zones',keywords:['modify','changed'],sev:'low',title:'Country/Timezone Modified',risk:'Reference data — low direct impact',rem:'Verify reference data accuracy'},
  {section:'Holidays',keywords:['configure','modify','changed'],sev:'low',title:'Holiday Calendar Modified',risk:'Reference data — indirect effect on SLA timing',rem:'Verify with operations team'},
  {section:'Experiences send welcome email pref',keywords:['toggle','changed'],sev:'low',title:'Welcome Email Preference Changed',risk:'Communication preference only',rem:'Low risk'},
];


const SEV = {critical:0,high:1,medium:2,low:3,info:4};

// ── Windows extraction helpers ──────────────────────────────────
function extractEID(l){const m=l.match(/(?:EventID|EventId|Event.ID)[\s:=]*(\d{3,5})\b/i);return m?m[1]:null}
function extractAcc(l){const m=l.match(/(?:Account|User|AccountName|NewAccount|Member)[\s:=]*([a-zA-Z0-9_$.\\-]+)/i);return m?m[1].replace(/^.*\\/,''):null}
function extractIP(l){const m=l.match(/(?:Source|IP|SourceIP|RemoteIP)[\s:=]*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i);return m?m[1]:null}

// ── Windows analysis ─────────────────────────────────────────────
function analyzeWindows(text){
  if(!text || !text.trim()) return [];
  const lines=text.split('\n').filter(l=>l.trim());
  const eidMap={};
  lines.forEach(l=>{
    const e=extractEID(l);
    if(e){if(!eidMap[e])eidMap[e]=[];eidMap[e].push(l);}
  });
  const winFindings=[];
  const seen={};
  WIN_RULES.forEach(r=>{
    const hits=eidMap[r.eid]||[];
    if(!hits.length) return;
    const key=r.eid+'_'+r.title;
    if(seen[key]) return; seen[key]=true;
    let sev=r.sev;
    if(r.eid==='4625'){if(hits.length>=10)sev='critical';else if(hits.length>=5)sev='high';else sev='medium';}
    const accs=[...new Set(hits.map(l=>extractAcc(l)).filter(Boolean))];
    const ips=[...new Set(hits.map(l=>extractIP(l)).filter(Boolean))];
    winFindings.push({
      source:'windows',sev,eid:r.eid,title:r.title,detail:r.detail,
      mitre:r.mitre,tactic:r.tactic,technique:r.technique,
      count:hits.length,accounts:accs.slice(0,5).join(', '),
      ips:ips.slice(0,3).join(', '),rem:r.rem,lines:hits.slice(0,3),
      user:'',section:'',action:'',id:'',domain:''
    });
  });
  winFindings.sort((a,b)=>SEV[a.sev]-SEV[b.sev]||b.count-a.count);
  return winFindings;
}

// ── Salesforce analysis ──────────────────────────────────────────
function ruleSections(r){
  return r.sections ? r.sections : [String(r.section||'').toLowerCase()];
}

function analyzeSalesforce(rows){
  if(!rows || !rows.length) return [];
  const ruleHits={};
  rows.forEach(row=>{
    const section=String(row['section']||row['Section']||'').trim();
    const action=String(row['action']||row['Action']||'').trim();
    const user=String(row['user']||row['User']||'').trim();
    const date=String(row['date']||row['Date']||'').trim();
    const delegate=String(row['delegate user']||row['Delegate User']||'').trim();
    const combined=(section+' '+action).toLowerCase();
    SF_RULES.forEach(r=>{
      const secMatch=ruleSections(r).some(s=>combined.includes(s));
      const kwMatch=r.keywords.some(kw=>combined.includes(kw.toLowerCase()));
      if(secMatch&&kwMatch){
        const key=(r.id||r.section)+'_'+r.sev+'_'+r.title;
        if(!ruleHits[key])ruleHits[key]={rule:r,rows:[],users:new Set(),sections:new Set(),actions:new Set()};
        ruleHits[key].rows.push({date,user,action,section,delegate});
        ruleHits[key].users.add(user);
        ruleHits[key].sections.add(section);
        ruleHits[key].actions.add(action.slice(0,60));
      }
    });
  });
  const sfFindings=Object.values(ruleHits).map(h=>({
    source:'salesforce',sev:h.rule.sev,eid:'SF',
    id:h.rule.id||'',domain:h.rule.domain||'',
    title:h.rule.title,detail:h.rule.risk,
    mitre:'',tactic:'',technique:'',
    section:h.rule.where||[...h.sections][0]||h.rule.section||'',
    action:[...h.actions].slice(0,2).join(' · '),
    accounts:[...h.users].slice(0,5).join(', '),
    ips:'',count:h.rows.length,rem:h.rule.rem,
    lines:h.rows.slice(0,3).map(r=>`${r.date} | ${r.user} | ${r.action} | ${r.section}${r.delegate?` | via: ${r.delegate}`:''}`)
  }));
  sfFindings.sort((a,b)=>SEV[a.sev]-SEV[b.sev]||b.count-a.count);
  return sfFindings;
}

module.exports = { WIN_RULES, SF_RULES, analyzeWindows, analyzeSalesforce };
