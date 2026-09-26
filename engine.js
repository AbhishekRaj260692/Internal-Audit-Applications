// ═══════════════════════════════════════════════════════════════
// PAM ANALYZE — SERVER-SIDE ENGINE (V25)
// The 183+ entry Oracle privilege library, PMWeb DAMAC-tailored
// findings, Form-Level Privileged Access Classification (6-tier +
// Combined Privileged Access across financial forms), and the
// External-User Privileged-Form-Access detection all run here.
// None of it reaches the browser — only the finished results JSON.
// ═══════════════════════════════════════════════════════════════

function col(headers,cands){
  const hl=headers.map(h=>(h||"").toLowerCase().trim());
  for(const c of cands){const i=hl.findIndex(h=>h.includes(c));if(i>=0)return headers[i];}
  return null;
}
function toast(msg,isErr){ /* no-op server-side (was a UI toast in the client build) */ }

const OR_LIB=[
{n:"Delete Supplier Bank Account",bp:"FIN",p:"Critical",cat:"Procurement Risk",w:"Alters bank account master data - fraud vector"},
{n:"Edit Supplier Registration Bank Account",bp:"FIN",p:"Critical",cat:"Procurement Risk",w:"Alters bank account master data - fraud vector"},
{n:"Maintain Ad Hoc Payments",bp:"FIN",p:"Critical",cat:"Admin-Equivalent (Masters/Workflow)",w:"Create ad hoc/one-off disbursement payments outside normal cycles"},
{n:"Maintain Bank Account Transfer",bp:"FIN",p:"Critical",cat:"Admin-Equivalent (Masters/Workflow)",w:"Alters bank account master data - fraud vector"},
{n:"Maintain Banks",bp:"FIN",p:"Critical",cat:"Admin-Equivalent (Masters/Workflow)",w:"Create/update bank, bank account, bank branch"},
{n:"Maintain Supplier Bank Accounts",bp:"FIN",p:"Critical",cat:"Procurement Risk",w:"Create/update/delete supplier bank account - fraud vector"},
{n:"Manage Bank",bp:"FIN",p:"Critical",cat:"Admin-Equivalent (Masters/Workflow)",w:"Create/update bank, bank account, bank branch"},
{n:"Manage Bank Account",bp:"FIN",p:"Critical",cat:"Admin-Equivalent (Masters/Workflow)",w:"Alters bank account master data - fraud vector"},
{n:"Manage Bank Account Approvals",bp:"FIN",p:"Critical",cat:"Admin-Equivalent (Masters/Workflow)",w:"Create/update bank, bank account, bank branch"},
{n:"Manage Bank Account Security",bp:"FIN",p:"Critical",cat:"Admin-Equivalent (Masters/Workflow)",w:"Create/update bank, bank account, bank branch"},
{n:"Manage Bank Account Transfer Security",bp:"FIN",p:"Critical",cat:"Admin-Equivalent (Masters/Workflow)",w:"Create/update bank, bank account, bank branch"},
{n:"Manage Payment File",bp:"FIN",p:"Critical",cat:"Admin-Equivalent (Masters/Workflow)",w:"Manage/transmit disbursement payment files - fraud vector"},
{n:"Manage Payment Instrument",bp:"FIN",p:"Critical",cat:"Admin-Equivalent (Masters/Workflow)",w:"Manage payment instrument configuration used in disbursements"},
{n:"Manage Supplier Bank Account",bp:"FIN",p:"Critical",cat:"Procurement Risk",w:"Alters supplier payment routing - classic fraud vector"},
{n:"Manage Supplier Bank Accounts",bp:"FIN",p:"Critical",cat:"Procurement Risk",w:"Alters bank account master data - fraud vector"},
{n:"Update Bank",bp:"FIN",p:"Critical",cat:"Admin-Equivalent (Masters/Workflow)",w:"Create/update bank, bank account, bank branch"},
{n:"Update Bank Account",bp:"FIN",p:"Critical",cat:"Admin-Equivalent (Masters/Workflow)",w:"Alters bank account master data - fraud vector"},
{n:"Update Supplier Bank Account",bp:"FIN",p:"Critical",cat:"Procurement Risk",w:"Alters bank account master data - fraud vector"},
{n:"Manage Database",bp:"FSM",p:"Critical",cat:"Privileged Role",w:"Manage underlying database configuration - infrastructure-level access"},
{n:"Manage Domain",bp:"FSM",p:"Critical",cat:"Privileged Role",w:"Manage environment/identity domain configuration"},
{n:"Manage Enterprise Environment",bp:"FSM",p:"Critical",cat:"Privileged Role",w:"Manage the enterprise environment configuration"},
{n:"Manage Data Security Profiles",bp:"HCM",p:"Critical",cat:"Direct Admin",w:"Alters row-level access policies and data security grants"},
{n:"Manage Payroll Payment Method",bp:"HCM",p:"Critical",cat:"Payroll Risk",w:"Alters how/where payroll funds are disbursed - fraud vector"},
{n:"Manage Payroll Payments",bp:"HCM",p:"Critical",cat:"Payroll Risk",w:"Process payroll payments / disbursement"},
{n:"Manage Payroll Personal Deduction",bp:"HCM",p:"Critical",cat:"Payroll Risk",w:"Alters third-party payee or deduction payment routing - fraud vector"},
{n:"Manage Payroll Third Parties",bp:"HCM",p:"Critical",cat:"Payroll Risk",w:"Manages third-party payees for payroll disbursement - fraud vector"},
{n:"Manage Payroll Third-Party Organization Payment Method",bp:"HCM",p:"Critical",cat:"Payroll Risk",w:"Create/modify/delete/assign payment method"},
{n:"Manage Payroll Third-Party Person Payment Method",bp:"HCM",p:"Critical",cat:"Payroll Risk",w:"Create/modify/delete/assign payment method"},
{n:"Edit Access Controls",bp:"RISK",p:"Critical",cat:"Direct Admin",w:"Modify access control definitions / SoD policy"},
{n:"Edit User",bp:"SEC",p:"Critical",cat:"Direct Admin",w:"Create/edit user, reset password, lock user"},
{n:"Edit User Roles",bp:"SEC",p:"Critical",cat:"Direct Admin",w:"Create/edit user, reset password, lock user"},
{n:"FND_MANAGE_AUDIT_POLICIES_PRIV",bp:"SEC",p:"Critical",cat:"Direct Admin",w:"Enable/disable auditing, configure audit objects/attributes"},
{n:"Manage Application Role",bp:"SEC",p:"Critical",cat:"Direct Admin",w:"Alters duty/application role definitions"},
{n:"Manage Application Security",bp:"SEC",p:"Critical",cat:"Direct Admin",w:"Manage roles, duty roles, job roles, data security policies, security console"},
{n:"Manage Audit Policies",bp:"SEC",p:"Critical",cat:"Direct Admin",w:"Configure/enable/disable audit policies"},
{n:"Manage Authentication Policies",bp:"SEC",p:"Critical",cat:"Direct Admin",w:"Configure MFA, SSO, federation, authentication policies"},
{n:"Manage Data Security",bp:"SEC",p:"Critical",cat:"Direct Admin",w:"Alters row-level access policies"},
{n:"Manage Data Security Grants",bp:"SEC",p:"Critical",cat:"Direct Admin",w:"Alters row-level access policies and data security grants"},
{n:"Manage Data Security Policies",bp:"SEC",p:"Critical",cat:"Direct Admin",w:"Alters row-level access policies and data security grants"},
{n:"Manage Duty Roles",bp:"SEC",p:"Critical",cat:"Direct Admin",w:"Alters duty/application role definitions"},
{n:"Manage Function Security",bp:"SEC",p:"Critical",cat:"Direct Admin",w:"Assign/remove/modify privileges, configure function security"},
{n:"Manage Identity Domain",bp:"SEC",p:"Critical",cat:"Direct Admin",w:"Manage identity domains, users, groups, identity roles/policies"},
{n:"Manage Identity Domains",bp:"SEC",p:"Critical",cat:"Direct Admin",w:"Manage identity domains, users, groups, identity roles/policies"},
{n:"Manage Identity Roles",bp:"SEC",p:"Critical",cat:"Direct Admin",w:"Manage identity domains, users, groups, identity roles/policies"},
{n:"Manage Privileges",bp:"SEC",p:"Critical",cat:"Direct Admin",w:"Assign/remove/modify privileges, configure function security"},
{n:"Manage Security Configuration",bp:"SEC",p:"Critical",cat:"Direct Admin",w:"Manage security console, roles, privileges, data security policies"},
{n:"Manage Security Console",bp:"SEC",p:"Critical",cat:"Direct Admin",w:"Manage security console, roles, privileges, data security policies"},
{n:"Manage User Account",bp:"SEC",p:"Critical",cat:"Direct Admin",w:"Create/edit user, reset password, lock user"},
{n:"Manage User Accounts",bp:"SEC",p:"Critical",cat:"Direct Admin",w:"Create/edit user, reset password, lock user"},
{n:"Manage User Details",bp:"SEC",p:"Critical",cat:"Direct Admin",w:"Create/edit user, reset password, lock user"},
{n:"Manage User Provisioning",bp:"SEC",p:"Critical",cat:"Direct Admin",w:"Create user, edit user roles, reset password"},
{n:"Manage User Role Provisioning",bp:"SEC",p:"Critical",cat:"Direct Admin",w:"Create user, edit user roles, reset password"},
{n:"Manage Users",bp:"SEC",p:"Critical",cat:"Direct Admin",w:"Create/edit user, reset password, lock user"},
{n:"Manage Data Access Sets",bp:"FIN",p:"High",cat:"Admin-Equivalent (Masters/Workflow)",w:"Assign data access sets to users"},
{n:"Manage Disbursement Payment Method",bp:"FIN",p:"High",cat:"Procurement Risk",w:"Create/modify/delete/assign payment method"},
{n:"Manage Payment Configuration",bp:"FIN",p:"High",cat:"Procurement Risk",w:"Payment formats, process profiles, payment methods"},
{n:"Manage Payment Formats",bp:"FIN",p:"High",cat:"Procurement Risk",w:"Payment formats, process profiles, payment methods"},
{n:"Manage Payment Method Defaulting Rule",bp:"FIN",p:"High",cat:"Procurement Risk",w:"Create/modify/delete/assign payment method"},
{n:"Manage Payment Process Profile",bp:"FIN",p:"High",cat:"Procurement Risk",w:"Payment formats, process profiles, payment methods"},
{n:"Manage Payment Process Profiles",bp:"FIN",p:"High",cat:"Procurement Risk",w:"Payment formats, process profiles, payment methods"},
{n:"Manage Payment System",bp:"FIN",p:"High",cat:"Procurement Risk",w:"Payment formats, process profiles, payment methods"},
{n:"Manage Subledger Accounting Rule",bp:"FIN",p:"High",cat:"Admin-Equivalent (Masters/Workflow)",w:"Alters how transactions post to the GL"},
{n:"Update Data Access Set",bp:"FIN",p:"High",cat:"Admin-Equivalent (Masters/Workflow)",w:"Create/modify/delete/assign data access sets - controls who can read/write which ledgers"},
{n:"Update Third Party Site Tax Profile",bp:"ATR",p:"High",cat:"Admin-Equivalent (Masters/Workflow)",w:"Alters third-party/supplier tax profile data"},
{n:"Update Third Party Tax Profile",bp:"ATR",p:"High",cat:"Admin-Equivalent (Masters/Workflow)",w:"Alters third-party/supplier tax profile data"},
{n:"Manage Enterprise Structures",bp:"FSM",p:"High",cat:"Admin-Equivalent (Masters/Workflow)",w:"Create legal entity, department, division"},
{n:"Delete Security Profile",bp:"HCM",p:"High",cat:"Direct Admin",w:"Create/modify/delete/assign security profile"},
{n:"Delete Workforce Structure",bp:"HCM",p:"High",cat:"Admin-Equivalent (Masters/Workflow)",w:"Create/modify/delete workforce structure"},
{n:"MANAGE BUSINESS UNIT",bp:"HCM",p:"High",cat:"Admin-Equivalent (Masters/Workflow)",w:"Create/update business unit, assign business function"},
{n:"MANAGE LEGAL ENTITY",bp:"HCM",p:"High",cat:"Admin-Equivalent (Masters/Workflow)",w:"Alters legal employer master data"},
{n:"Maintain Business Units",bp:"HCM",p:"High",cat:"Admin-Equivalent (Masters/Workflow)",w:"Create/update business unit, assign business function"},
{n:"Maintain Enterprise Structures",bp:"HCM",p:"High",cat:"Admin-Equivalent (Masters/Workflow)",w:"Create legal entity, department, division"},
{n:"Maintain Security Profiles",bp:"HCM",p:"High",cat:"Admin-Equivalent (Masters/Workflow)",w:"Create/modify/delete/assign security profile"},
{n:"Manage Employee Payroll in Employment Processes",bp:"HCM",p:"High",cat:"Admin-Equivalent (Masters/Workflow)",w:"Manage payroll records within employment processes"},
{n:"Manage Enterprise Structure",bp:"HCM",p:"High",cat:"Admin-Equivalent (Masters/Workflow)",w:"Alters legal employer / business unit structures"},
{n:"Manage HCM Data Roles",bp:"HCM",p:"High",cat:"Admin-Equivalent (Masters/Workflow)",w:"Create/update HCM data role, assign security profile"},
{n:"Manage HCM Security",bp:"HCM",p:"High",cat:"Admin-Equivalent (Masters/Workflow)",w:"Configure HCM security, HCM data roles, person security profiles"},
{n:"Manage Payroll Administration Work Area",bp:"HCM",p:"High",cat:"Payroll Risk",w:"Payroll administration setup"},
{n:"Manage Payroll Calculation Work Area",bp:"HCM",p:"High",cat:"Payroll Risk",w:"Payroll calculation setup"},
{n:"Manage Payroll Definition",bp:"HCM",p:"High",cat:"Payroll Risk",w:"Alters payroll calculation setup"},
{n:"Manage Payroll Element",bp:"HCM",p:"High",cat:"Payroll Risk",w:"Alters pay elements feeding payroll calculations"},
{n:"Manage Payroll Element Entry",bp:"HCM",p:"High",cat:"Payroll Risk",w:"Alters pay elements feeding payroll calculations"},
{n:"Manage Payroll Relationship",bp:"HCM",p:"High",cat:"Payroll Risk",w:"Manage payroll relationship records linking worker to payroll"},
{n:"Manage Person",bp:"HCM",p:"High",cat:"Admin-Equivalent (Masters/Workflow)",w:"Creates/updates worker personal/master data"},
{n:"Manage Person Number",bp:"HCM",p:"High",cat:"Admin-Equivalent (Masters/Workflow)",w:"Creates/updates worker personal/master data"},
{n:"Manage Security Profiles",bp:"HCM",p:"High",cat:"Admin-Equivalent (Masters/Workflow)",w:"Create/modify/delete/assign security profile"},
{n:"Update HCM Data Role",bp:"HCM",p:"High",cat:"Admin-Equivalent (Masters/Workflow)",w:"Create/update HCM data role, assign security profile"},
{n:"Delete REST Service",bp:"INT",p:"High",cat:"Integration/Service Access",w:"Register/modify/delete/secure REST service"},
{n:"Delete SOAP Service",bp:"INT",p:"High",cat:"Integration/Service Access",w:"Register/modify/delete/secure SOAP service"},
{n:"Maintain API Security",bp:"INT",p:"High",cat:"Integration/Service Access",w:"Configure OAuth, manage API credentials, assign API roles"},
{n:"Maintain Certificates",bp:"INT",p:"High",cat:"Integration/Service Access",w:"Secure integration credentials, certificates, and trust configuration"},
{n:"Manage API Credentials",bp:"INT",p:"High",cat:"Integration/Service Access",w:"Configure OAuth, manage API credentials, assign API roles"},
{n:"Manage API Security",bp:"INT",p:"High",cat:"Integration/Service Access",w:"Configure OAuth, manage API credentials, assign API roles"},
{n:"Manage Connections",bp:"INT",p:"High",cat:"Integration/Service Access",w:"Manage REST/SOAP services, OIC connections, web services"},
{n:"Manage FBDI Imports",bp:"INT",p:"High",cat:"Integration/Service Access",w:"Upload/import/validate FBDI file, submit import job"},
{n:"Manage Integration Credentials",bp:"INT",p:"High",cat:"Integration/Service Access",w:"Secure integration credentials, certificates, and trust configuration"},
{n:"Manage Integration Security",bp:"INT",p:"High",cat:"Integration/Service Access",w:"Secure integration credentials, certificates, and trust configuration"},
{n:"Manage Integration Services",bp:"INT",p:"High",cat:"Integration/Service Access",w:"Manage REST/SOAP services, OIC connections, web services"},
{n:"Manage OIC Connections",bp:"INT",p:"High",cat:"Integration/Service Access",w:"Manage REST/SOAP services, OIC connections, web services"},
{n:"Manage REST APIs",bp:"INT",p:"High",cat:"Integration/Service Access",w:"Register/modify/delete/secure REST service"},
{n:"Manage REST Services",bp:"INT",p:"High",cat:"Integration/Service Access",w:"Register/modify/delete/secure REST service"},
{n:"Manage SOAP Services",bp:"INT",p:"High",cat:"Integration/Service Access",w:"Register/modify/delete/secure SOAP service"},
{n:"Delete Payment Method",bp:"PROC",p:"High",cat:"Procurement Risk",w:"Create/modify/delete/assign payment method"},
{n:"Manage File Import and Export",bp:"PROC",p:"High",cat:"Integration/Service Access",w:"Execute FBDI/HDL/file import, submit import jobs"},
{n:"Manage Payment Methods",bp:"PROC",p:"High",cat:"Procurement Risk",w:"Create/modify/delete/assign payment method"},
{n:"Delete Role Hierarchy",bp:"SEC",p:"High",cat:"Direct Admin",w:"Create/update/delete role hierarchy and inheritance"},
{n:"Edit Role Hierarchy",bp:"SEC",p:"High",cat:"Direct Admin",w:"Create/update/delete role hierarchy and inheritance"},
{n:"Maintain Role Inheritance",bp:"SEC",p:"High",cat:"Direct Admin",w:"Create/update/delete role hierarchy and inheritance"},
{n:"Manage Groups",bp:"SEC",p:"High",cat:"Direct Admin",w:"Manage user groups and group-based access assignments"},
{n:"Manage Job Roles",bp:"SEC",p:"High",cat:"Direct Admin",w:"Create/edit job or duty roles, role hierarchy, copy roles"},
{n:"Manage Role Delegations",bp:"SEC",p:"High",cat:"Direct Admin",w:"Alters who can act as an approver on another user's behalf"},
{n:"Manage Role Hierarchy",bp:"SEC",p:"High",cat:"Direct Admin",w:"Create/update/delete role hierarchy and inheritance"},
{n:"Manage Role Provisioning",bp:"SEC",p:"High",cat:"Direct Admin",w:"Controls automatic role grants"},
{n:"Manage Roles",bp:"SEC",p:"High",cat:"Direct Admin",w:"Create/edit job or duty roles, role hierarchy, copy roles"},
{n:"Manage Security Roles",bp:"SEC",p:"High",cat:"Direct Admin",w:"Create/edit job or duty roles, role hierarchy, copy roles"},
{n:"Manage User Roles",bp:"SEC",p:"High",cat:"Direct Admin",w:"Assign/remove roles and data roles for users"},
{n:"Mass Edit Security Assignments",bp:"SEC",p:"High",cat:"Direct Admin",w:"Bulk update role assignments across many users"},
{n:"Update Role Hierarchy",bp:"SEC",p:"High",cat:"Direct Admin",w:"Create/update/delete role hierarchy and inheritance"},
{n:"Delete Approval Rule",bp:"BPM",p:"High",cat:"Direct Admin",w:"Create/update/delete/publish/activate/validate approval rule"},
{n:"Manage Approval Groups",bp:"BPM",p:"High",cat:"Direct Admin",w:"Create/modify/delete/assign approval group"},
{n:"Manage Approval Rules",bp:"BPM",p:"High",cat:"Direct Admin",w:"Create/update/delete/publish/activate/validate approval rule"},
{n:"Manage Approval Task",bp:"BPM",p:"High",cat:"Direct Admin",w:"Create/update/delete approval rule, approval groups/routing"},
{n:"Manage Approval Tasks",bp:"BPM",p:"High",cat:"Direct Admin",w:"Create/update/delete approval rule, approval groups/routing"},
{n:"Manage BPM Worklists",bp:"BPM",p:"High",cat:"Direct Admin",w:"Manage BPM worklists, workflow config, approval routing"},
{n:"Manage Task Configuration",bp:"BPM",p:"High",cat:"Direct Admin",w:"Can alter approval workflow rules"},
{n:"Manage Task Configurations",bp:"BPM",p:"High",cat:"Direct Admin",w:"Can alter approval workflow rules"},
{n:"Manage Workflow Rules",bp:"BPM",p:"High",cat:"Direct Admin",w:"Can alter approval workflow rules"},
{n:"Update Approval Rule",bp:"BPM",p:"High",cat:"Direct Admin",w:"Create/update/delete/publish/activate/validate approval rule"},
{n:"Update Task Outcome",bp:"BPM",p:"High",cat:"Direct Admin",w:"Can force an approval decision"},
{n:"Delete BI Folder",bp:"BI",p:"Medium",cat:"Reporting/BI Access",w:"Create/modify/delete BI folder, publish BI content"},
{n:"Edit SQL",bp:"BI",p:"Medium",cat:"Reporting/BI Access",w:"Create data model, modify SQL/data set, configure data source"},
{n:"Manage BI Catalog",bp:"BI",p:"Medium",cat:"Reporting/BI Access",w:"Create/modify/delete BI folder, publish BI content"},
{n:"Manage BI Publisher",bp:"BI",p:"Medium",cat:"Reporting/BI Access",w:"Create/modify report, manage catalog, configure report security"},
{n:"Manage Data Models",bp:"BI",p:"Medium",cat:"Reporting/BI Access",w:"Create data model, modify SQL/data set, configure data source"},
{n:"Manage Report Access",bp:"BI",p:"Medium",cat:"Reporting/BI Access",w:"Assign/remove report permissions, manage report access"},
{n:"Manage Report Catalog",bp:"BI",p:"Medium",cat:"Reporting/BI Access",w:"Manage the report catalog folder structure and access"},
{n:"Manage Report Security",bp:"BI",p:"Medium",cat:"Reporting/BI Access",w:"Assign/remove report permissions, manage report access"},
{n:"Maintain Accounting Calendar",bp:"FIN",p:"Medium",cat:"Privileged Role",w:"Create calendar, open/close accounting period"},
{n:"Maintain Enterprise Configuration",bp:"FIN",p:"Medium",cat:"Privileged Role",w:"Setup & Maintenance, implementation projects, functional areas"},
{n:"Maintain Period Status",bp:"FIN",p:"Medium",cat:"Privileged Role",w:"Open/close/reopen accounting period"},
{n:"Manage All Application Profile Values",bp:"FIN",p:"Medium",cat:"Privileged Role",w:"Create/update/delete profile option, manage system profile"},
{n:"Manage Enterprise Offerings",bp:"FIN",p:"Medium",cat:"Privileged Role",w:"Configure offerings, functional areas, enterprise profile"},
{n:"Manage Functional Setup",bp:"FIN",p:"Medium",cat:"Direct Admin",w:"Setup & Maintenance, implementation projects, functional areas"},
{n:"Manage Implementation Projects",bp:"FIN",p:"Medium",cat:"Privileged Role",w:"Setup & Maintenance, implementation projects, functional areas"},
{n:"Manage Period Close",bp:"FIN",p:"Medium",cat:"Privileged Role",w:"Opens/closes accounting periods"},
{n:"Update Calendar",bp:"FIN",p:"Medium",cat:"Privileged Role",w:"Create calendar, open/close accounting period"},
{n:"Manage Accounting Calendar",bp:"ATR",p:"Medium",cat:"Privileged Role",w:"Create calendar, open/close accounting period"},
{n:"Delete Lookup",bp:"FSM",p:"Medium",cat:"Privileged Role",w:"Create/update/delete/enable/disable lookup"},
{n:"Delete Profile Option",bp:"FSM",p:"Medium",cat:"Privileged Role",w:"Create/update/delete profile option, manage system profile"},
{n:"Delete Reference Data Set",bp:"FSM",p:"Medium",cat:"Reporting/BI Access",w:"Create/modify/assign/delete/publish reference data set"},
{n:"Delete Value Set",bp:"FSM",p:"Medium",cat:"Privileged Role",w:"Create/update/delete/assign value set"},
{n:"Manage Application Descriptive Flexfield",bp:"FSM",p:"Medium",cat:"Privileged Role",w:"Deploy/compile/publish flexfield changes; manage descriptive/key/extensible flexfields, value sets"},
{n:"Manage Application Extensible Flexfield",bp:"FSM",p:"Medium",cat:"Privileged Role",w:"Deploy/compile/publish flexfield changes; manage descriptive/key/extensible flexfields, value sets"},
{n:"Manage Application Flexfield Value Set",bp:"FSM",p:"Medium",cat:"Privileged Role",w:"Deploy/compile/publish flexfield changes; manage descriptive/key/extensible flexfields, value sets"},
{n:"Manage Descriptive Flexfields",bp:"FSM",p:"Medium",cat:"Privileged Role",w:"Deploy/compile/publish flexfield changes; manage descriptive/key/extensible flexfields, value sets"},
{n:"Manage Enterprise Profile",bp:"FSM",p:"Medium",cat:"Privileged Role",w:"Configure offerings, functional areas, enterprise profile"},
{n:"Manage Flexfields",bp:"FSM",p:"Medium",cat:"Privileged Role",w:"Manage descriptive/key flexfields, extensible flexfields, value sets"},
{n:"Manage Functional Areas",bp:"FSM",p:"Medium",cat:"Privileged Role",w:"Configure offerings, functional areas, enterprise profile"},
{n:"Manage Key Flexfields",bp:"FSM",p:"Medium",cat:"Privileged Role",w:"Deploy/compile/publish flexfield changes; manage descriptive/key/extensible flexfields, value sets"},
{n:"Manage Lookups",bp:"FSM",p:"Medium",cat:"Privileged Role",w:"Create/update/delete/enable/disable lookup"},
{n:"Manage Profile Options",bp:"FSM",p:"Medium",cat:"Privileged Role",w:"Create/update/delete profile option, manage system profile"},
{n:"Manage Reference Data Sets",bp:"FSM",p:"Medium",cat:"Reporting/BI Access",w:"Create/modify/assign/delete/publish reference data set"},
{n:"Manage Sandbox",bp:"FSM",p:"Medium",cat:"Privileged Role",w:"Create/manage/import/export/publish/merge sandbox"},
{n:"Manage Setup and Maintenance",bp:"FSM",p:"Medium",cat:"Direct Admin",w:"Setup & Maintenance, implementation projects, functional areas"},
{n:"Manage Value Sets",bp:"FSM",p:"Medium",cat:"Privileged Role",w:"Create/update/delete/assign value set"},
{n:"Setup and Maintain Applications",bp:"FSM",p:"Medium",cat:"Direct Admin",w:"Setup & Maintenance, implementation projects, functional areas"},
{n:"Update Lookup",bp:"FSM",p:"Medium",cat:"Privileged Role",w:"Create/update/delete/enable/disable lookup"},
{n:"Update Profile Option",bp:"FSM",p:"Medium",cat:"Privileged Role",w:"Create/update/delete profile option, manage system profile"},
{n:"Update Value Set",bp:"FSM",p:"Medium",cat:"Privileged Role",w:"Create/update/delete/assign value set"},
{n:"Manage Integration Packages",bp:"INT",p:"Medium",cat:"Integration/Service Access",w:"Manage integrations, connections, packages, security, endpoints"},
{n:"Manage Integrations",bp:"INT",p:"Medium",cat:"Integration/Service Access",w:"Manage integrations, connections, packages, security, endpoints"},
{n:"Maintain Bursting Definitions",bp:"BI",p:"Low",cat:"Reporting/BI Access",w:"Configure/maintain/schedule report bursting definitions"},
{n:"Manage Report Bursting",bp:"BI",p:"Low",cat:"Reporting/BI Access",w:"Configure/maintain/schedule report bursting definitions"},
{n:"Manage Supplier",bp:"PROC",p:"High",cat:"Procurement Risk",w:"Create/modify/delete/assign supplier"},
{n:"Maintain Supplier",bp:"PROC",p:"High",cat:"Procurement Risk",w:"Create/modify/delete/assign supplier"},
{n:"Maintain Supplier Master Data",bp:"PROC",p:"High",cat:"Procurement Risk",w:"Create/modify/delete/assign supplier"}
];

// Exact-match index over the curated privilege library (case-insensitive,
// full-name match only).
const OR_LIB_INDEX=new Map();
OR_LIB.forEach(e=>OR_LIB_INDEX.set(e.n.toLowerCase().trim(),e));



// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PMWEB ACCESS-CONTROL ENGINE (unchanged from the merged build)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// 1. Risk configuration (editable at runtime via the sidebar)
const PM_CONFIG={
  APPROVED_DOMAINS:["damacgroup.com","damacsharedservices.com","loams.com","whitespot.ae"],
  GENERIC_PATTERNS:["admin","support","test","uat","user1","user2","user3","bot","rpa","service","shared","generic","powerbi","train"],
  SERVICE_KEYWORDS:["rpa","bot","service","powerbi","integration"],
  TEST_PATTERNS:["test","uat","train","dummy","sample"],
  CRITICAL_MODULES:["Security","Role Manager","Form Builder","Integration Manager","Business Processes","User Defined Fields","Projects","Programs","Companies","A/P Payments","Journal Entries","Cost Ledger","Commitments","Commitment COs","Progress Invoices","Budgets","Budget Requests","Periods","Settings","Email Setup"],
  FINANCIAL_MODULES:["A/P Payments","Journal Entries","Cost Ledger","Commitments","Commitment CO","IPC","Progress Invoices","Budgets","Budget Requests"],
  ADMIN_SCORE_THRESHOLD:100,
  ADMIN_NAME_KEYWORDS:["administrator","system admin","super admin","superadmin","system administrator","global admin","full access","all access"],
  EXT_GROUP_PREFIX:/^ext[-_]/i,
  LOW_PRIV_LICENCES:["guest"],
};

// 2. Permission scoring
const PERMISSION_SCORE={"View":1,"View & Edit":3,"View, Create & Edit":5,"Delete":7,"Full Control":10};
function scorePermission(permRaw){
  const p=String(permRaw||"").replace(/\u00A0/g," ").replace(/\s+/g," ").trim();
  if(PERMISSION_SCORE.hasOwnProperty(p))return PERMISSION_SCORE[p];
  const pl=p.toLowerCase();
  if(!pl||["none","-","n/a","no access","no","0","false"].includes(pl))return 0;
  if(pl.includes("full"))return 10;
  if(pl.includes("delete"))return 7;
  if(pl.includes("create")&&pl.includes("edit"))return 5;
  if(pl.includes("edit")||pl.includes("modify")||pl.includes("update"))return 3;
  if(pl.includes("view"))return 1;
  return 2;
}

// 3. Helpers
function getDomain(id){const m=String(id||"").match(/@([a-z0-9.-]+\.[a-z]{2,})/i);return m?m[1].toLowerCase():"";}
let _internalAuto=false;
function isExternalUser(id){
  const domain=getDomain(id);
  if(_internalAuto){
    return orgDomainAuto&&domain&&domain!==orgDomainAuto;
  }
  if(!domain)return false;
  return !PM_CONFIG.APPROVED_DOMAINS.includes(domain);
}
// Normalizes a group/column name for matching purposes: collapses
// non-breaking spaces and repeated whitespace, trims, lowercases. Real
// Excel exports very commonly introduce trailing spaces, double spaces, or
// non-breaking spaces (U+00A0, e.g. from pasted content) into either the
// User Access Report's Group column or the Group Access Matrix's column
// headers — a naive .trim().toLowerCase() misses these, silently causing
// a user's group to fail to match any matrix column, which then gives that
// user ZERO effective access rows with no visible error.
function normText(s){
  return String(s||"").replace(/\u00A0/g," ").replace(/\s+/g," ").trim().toLowerCase();
}
// Aggressive fallback normalizer, used only when an exact normText match
// fails. Strips the kind of noise commonly seen in real PMWeb group lists:
// leading enumeration ("1) Procurement L3 ..."), parenthetical suffixes
// ("... (Menon Team)"), and inconsistent punctuation/hyphen spacing
// ("EXT-Contractors - X" vs "EXT-Contractors -X" vs "EXT-Contractors- X").
// Two names that only differ by this kind of noise will normalize to the
// same superNorm key and can still be safely matched.
function superNorm(s){
  let t=String(s||"").replace(/\u00A0/g," ").toLowerCase();
  t=t.replace(/^\s*\d+\)\s*/,"");           // leading "1) "
  t=t.replace(/[().,]/g," ");               // parens/periods/commas -> space
  t=t.replace(/[-_]+/g," ");                // hyphens/underscores -> space
  t=t.replace(/\s+/g," ").trim();
  return t;
}
function tokenize(text){
  return String(text||"").split(/[^a-zA-Z0-9]+/).filter(Boolean);
}
function tokenMatchesKeyword(token,keyword){
  const tokenLower=token.toLowerCase();
  if(tokenLower===keyword)return true;
  if(tokenLower.startsWith(keyword)){
    const rest=tokenLower.slice(keyword.length);
    if(rest.length>0&&/^\d+$/.test(rest))return true; // keyword+digits, e.g. "bot1"
    // Acronym-prefix compound word, e.g. "RPAlogin": only counts as a match
    // if the token is NOT entirely uppercase AND the character right after
    // the matched prefix is lowercase — both signal a genuine acronym
    // boundary. Without this guard, a real person's name exported in
    // ALL-CAPS (a common Oracle HR/IT extract convention, e.g.
    // "BOTHAYNA.TAWFIK") would trivially satisfy "prefix===prefix.toUpperCase()"
    // for ANY name that happens to start with the same letters as a keyword
    // ("BOT" is the first three letters of "BOTHAYNA") and get misclassified
    // as a bot/service account — this was a real, confirmed false positive.
    if(token!==token.toUpperCase()){
      const prefix=token.slice(0,keyword.length);
      const nextChar=token.slice(keyword.length,keyword.length+1);
      if(prefix.length===keyword.length&&prefix===prefix.toUpperCase()&&/[A-Z]/.test(prefix)&&nextChar&&nextChar===nextChar.toLowerCase()&&/[a-z]/.test(nextChar))return true;
    }
  }
  return false;
}
function matchesAnyKeyword(localPart,keywords){
  const tokens=tokenize(localPart);
  return keywords.some(k=>tokens.some(t=>tokenMatchesKeyword(t,k)));
}
function isGenericAccount(userid){
  const local=String(userid||"").split("@")[0];
  return matchesAnyKeyword(local,PM_CONFIG.GENERIC_PATTERNS);
}
function isServiceAccount(userid){
  const local=String(userid||"").split("@")[0];
  return matchesAnyKeyword(local,PM_CONFIG.SERVICE_KEYWORDS);
}
function isTestAccount(userid){
  const local=String(userid||"").split("@")[0];
  return matchesAnyKeyword(local,PM_CONFIG.TEST_PATTERNS);
}
function isAdminGroupName(groupName){
  if(!groupName)return false;
  const g=normText(groupName);
  if(g==="admin")return true;
  return PM_CONFIG.ADMIN_NAME_KEYWORDS.some(k=>g.includes(k));
}
function moduleIsCritical(form){
  const f=String(form||"").toLowerCase();
  return PM_CONFIG.CRITICAL_MODULES.some(m=>f.includes(m.toLowerCase()));
}
function moduleIsFinancial(form){
  const f=String(form||"").toLowerCase();
  return PM_CONFIG.FINANCIAL_MODULES.some(m=>f.includes(m.toLowerCase()));
}

// 4. Build flat effective-access rows
function buildUserPermissions(userAccessData,groupAccessFlat){
  const permissions=[];
  const byGroup={};
  groupAccessFlat.forEach(r=>{const k=normText(r.group);if(!byGroup[k])byGroup[k]=[];byGroup[k].push(r);});
  userAccessData.forEach(user=>{
    const gk=normText(user.group);
    const rows=byGroup[gk]||[];
    rows.forEach(r=>{
      permissions.push({userid:user.id,name:user.name,license:user.license,group:user.group,form:r.form,permission:r.permission,score:scorePermission(r.permission)});
    });
  });
  return permissions;
}
function calculateGroupRisk(groupName,groupAccessFlat){
  let score=0;
  const gnorm=normText(groupName);
  groupAccessFlat.forEach(r=>{
    if(normText(r.group)!==gnorm)return;
    if(moduleIsCritical(r.form))score+=scorePermission(r.permission);
  });
  return score;
}
function getAdminEquivalentGroups(groupAccessFlat){
  const scoreByGroup=new Map();
  groupAccessFlat.forEach(r=>{
    if(!moduleIsCritical(r.form))return;
    const gk=normText(r.group);
    scoreByGroup.set(gk,(scoreByGroup.get(gk)||0)+scorePermission(r.permission));
  });
  const originalCase=new Map();
  groupAccessFlat.forEach(r=>{const gk=normText(r.group);if(!originalCase.has(gk))originalCase.set(gk,r.group);});
  const findings=[];
  scoreByGroup.forEach((score,gk)=>{
    if(score>=PM_CONFIG.ADMIN_SCORE_THRESHOLD){
      findings.push({group:originalCase.get(gk)||gk,score,severity:"Critical",finding:"Admin Equivalent Access"});
    }
  });
  return findings;
}
function detectAdminUsers(userAccessData){
  return userAccessData.filter(u=>isAdminGroupName(u.group)).map(u=>({userid:u.id,name:u.name,group:u.group,severity:"Critical",finding:"Direct Administrator"}));
}
function calculateGroupAverageScore(groupAccessFlat){
  const stats={};
  groupAccessFlat.forEach(r=>{
    const gk=normText(r.group);
    if(!stats[gk])stats[gk]={sum:0,count:0};
    stats[gk].sum+=scorePermission(r.permission);
    stats[gk].count+=1;
  });
  const avg={};
  Object.keys(stats).forEach(gk=>{avg[gk]=stats[gk].count?stats[gk].sum/stats[gk].count:0;});
  return avg;
}
function detectAdminByAverageAccess(userAccessData,groupAccessFlat){
  const avgByGroup=calculateGroupAverageScore(groupAccessFlat);
  return userAccessData.filter(u=>{
    const gk=normText(u.group);
    return gk&&avgByGroup[gk]>7;
  }).map(u=>{
    const gk=normText(u.group);
    return {userid:u.id,name:u.name,group:u.group,severity:"Critical",finding:"Direct Administrator (Average Access Level > 7)",avgScore:Math.round(avgByGroup[gk]*10)/10};
  });
}
function detectGenericAccounts(userAccessData){
  return userAccessData.filter(u=>isGenericAccount(u.id)).map(u=>({userid:u.id,group:u.group,severity:"Critical",finding:"Generic Account"}));
}
function detectExternalUsers(userAccessData){
  return userAccessData.filter(u=>isExternalUser(u.id)).map(u=>({userid:u.id,group:u.group,domain:getDomain(u.id),severity:"Medium",finding:"External User"}));
}
function groupPermsByUser(userPermissions){
  const map=new Map();
  for(let i=0;i<userPermissions.length;i++){
    const p=userPermissions[i];
    let arr=map.get(p.userid);
    if(!arr){arr=[];map.set(p.userid,arr);}
    arr.push(p);
  }
  return map;
}
function detectServiceAccounts(userAccessData,userPermissions,permsByUser){
  const findings=[];
  const byUser=permsByUser||groupPermsByUser(userPermissions);
  userAccessData.forEach(u=>{
    if(!isServiceAccount(u.id))return;
    const perms=byUser.get(u.id)||[];
    const criticalAccess=perms.some(p=>moduleIsCritical(p.form)&&p.score>=5);
    findings.push({userid:u.id,group:u.group,severity:criticalAccess?"Critical":"Medium",finding:"Privileged Service Account"});
  });
  return findings;
}
function detectSoDConflicts(userPermissions,permsByUser){
  const findings=[];
  const byUser=permsByUser||groupPermsByUser(userPermissions);
  byUser.forEach((rows,user)=>{
    const risky=rows.filter(r=>moduleIsFinancial(r.form)&&r.score>=5);
    const uniqueModules=[...new Set(risky.map(r=>r.form))];
    if(uniqueModules.length>=3){
      findings.push({userid:user,modules:uniqueModules,severity:"High",finding:"Segregation Of Duties Conflict"});
    }
  });
  return findings;
}
function detectContractorInvoiceAccess(userPermissions){
  return userPermissions.filter(p=>PM_CONFIG.EXT_GROUP_PREFIX.test(String(p.group||""))&&String(p.form||"").toLowerCase().includes("progress invoice")&&p.score>=3)
    .map(p=>({userid:p.userid,group:p.group,severity:"High",finding:"External User Can Modify Invoice Records"}));
}
function detectTestAccounts(userAccessData){
  return userAccessData.filter(u=>isTestAccount(u.id)).map(u=>({userid:u.id,group:u.group,severity:"High",finding:"Test Or UAT Account"}));
}
function buildExecutiveSummary(data){
  return{
    adminUsers:data.adminUsers.length,
    adminByAverageAccess:(data.adminByAverageAccess||[]).length,
    genericAccounts:data.genericAccounts.length,
    externalUsers:data.externalUsers.length,
    externalPrivileged:0, // populated after form-level classification runs, see analysePM
    serviceAccounts:data.serviceAccounts.length,
    sodConflicts:data.sodConflicts.length,
    adminEquivalentGroups:data.adminEquivalentGroups.length,
    testAccounts:data.testAccounts.length,
    contractorAccess:data.contractorAccess.length
  };
}
function generateFinding(title,risk,affectedUsers,recommendation,impact){
  // Accepts either plain username strings (PMWeb) or objects carrying
  // {userid, role, privileges} (Oracle) — normalized here so the render
  // and export code can handle both uniformly, deduped by userid.
  const normalized=(affectedUsers||[]).map(u=>typeof u==="string"?{userid:u}:u);
  const seen=new Set();
  const deduped=[];
  normalized.forEach(u=>{ if(u&&u.userid&&!seen.has(u.userid)){ seen.add(u.userid); deduped.push(u); } });
  return{title,risk,affectedUsers:deduped,impact:impact||"",recommendation};
}
function buildAuditFindings(result){
  const list=[];
  if(result.adminUsers.length)list.push(generateFinding("Direct Administrator Access","Critical",result.adminUsers.map(u=>u.userid),"Recertify all admin-group users; reduce standing population to the minimum required and split security/config/workflow duties.","Unrestricted ability to view, create, edit and delete records, manage users/groups and change system configuration."));
  if(result.adminEquivalentGroups.length)list.push(generateFinding("Admin-Equivalent Group (Weighted Score)","Critical",result.adminEquivalentGroups.map(g=>`${g.group} (score ${g.score})`),"Classify these groups as privileged even though they are not named 'admin'; split security, configuration, integration and business-support duties.","Full Control-level access across security and financial-configuration modules despite an innocuous group name."));
  if(result.genericAccounts.length)list.push(generateFinding("Generic / Shared Account","Critical",result.genericAccounts.map(u=>u.userid),"Replace with named, individually attributable accounts; vault any credential that must remain shared as break-glass only.","Actions cannot be attributed to one person; password sharing and accountability risk."));
  if(result.serviceAccounts.length)list.push(generateFinding("Privileged Service Account","Critical",result.serviceAccounts.map(u=>u.userid),"Restrict bot/RPA/reporting accounts to least-privilege, non-interactive scopes; vault and auto-rotate credentials.","Compromise of a service credential could allow modification of workflows, security configuration or financial records."));
  if(result.externalPrivileged&&result.externalPrivileged.length)list.push(generateFinding("External User — Privileged Form Access (Full Control / Edit+Delete)","Critical",result.externalPrivileged,"External/contractor accounts should never hold Full Control, or a combined Edit+Delete, on any form. Restrict to view/create-only access, or formally justify and time-box the elevated grant with a named business sponsor.","An external-domain account holds Full Control, Privileged (Create+Edit+Delete), or Admin-Equivalent (Edit+Delete) access on at least one form — this exceeds what an external party should normally require and is a significant fraud/data-integrity risk if the account is compromised or acting adversarially."));
  if(result.contractorAccess.length)list.push(generateFinding("External User Can Modify Invoice Records","High",result.contractorAccess.map(u=>u.userid),"Restrict external/contractor access to draft creation, editing pre-submission and status viewing only; remove certify/approve/post/delete rights.","Contractor may be able to prepare or alter records supporting its own payment — self-interest and SoD risk."));
  if(result.sodConflicts.length)list.push(generateFinding("Segregation Of Duties Conflict","High",result.sodConflicts.map(u=>u.userid),"Separate measurement/valuation, invoice preparation, commercial certification, budget validation and payment posting across different users.","A single user spans 3+ financial modules with edit/full rights, enabling undetected end-to-end control of a transaction."));
  if(result.testAccounts.length)list.push(generateFinding("Test / UAT / Training Account","High",result.testAccounts.map(u=>u.userid),"Disable unless a current approved testing window exists; apply automatic expiry to all test and external accounts.","Test identities in production can bypass normal joiner/approval controls and are often unattributed to an accountable owner."));
  if(result.externalUsers.length)list.push(generateFinding("External-Domain User","Medium",result.externalUsers.map(u=>u.userid),"Confirm each external account has a documented business sponsor, project scope and expiry date.","Baseline visibility into how many accounts sit outside the approved/internal domain list."));
  return list;
}
function runPMWebAssessment(userAccessData,groupAccessFlat){
  const userPermissions=buildUserPermissions(userAccessData,groupAccessFlat);
  const permsByUser=groupPermsByUser(userPermissions);
  const adminByName=detectAdminUsers(userAccessData);
  const adminByAverage=detectAdminByAverageAccess(userAccessData,groupAccessFlat);
  const adminMap=new Map();
  adminByName.forEach(u=>adminMap.set(u.userid,u));
  adminByAverage.forEach(u=>{if(!adminMap.has(u.userid))adminMap.set(u.userid,u);});
  const result={
    adminUsers:[...adminMap.values()],
    adminByAverageAccess:adminByAverage,
    genericAccounts:detectGenericAccounts(userAccessData),
    externalUsers:detectExternalUsers(userAccessData),
    externalPrivileged:[], // populated after form-level classification runs, see analysePM
    serviceAccounts:detectServiceAccounts(userAccessData,userPermissions,permsByUser),
    sodConflicts:detectSoDConflicts(userPermissions,permsByUser),
    contractorAccess:detectContractorInvoiceAccess(userPermissions),
    adminEquivalentGroups:getAdminEquivalentGroups(groupAccessFlat),
    testAccounts:detectTestAccounts(userAccessData)
  };
  result.summary=buildExecutiveSummary(result);
  result.userPermissions=userPermissions;
  result.narrativeFindings=buildAuditFindings(result);
  return result;
}
const PM_LIB={
  critForms:["contract","cost management","purchase order","invoice","change order","payment","budget","commitment","funding","prime contract","subcontract","vendor","supplier","bank","workflow configuration","system configuration","user management","role management","security","audit","journal","general ledger","master data","cost ledger","progress invoice","a/p payment","commitment co"],
  critPerms:["full","admin","configure","delete","approve","authorize","all","manage","setup","execute"],
  highForms:["rfq","rfp","bid","tender","material","equipment","resource","timesheet","schedule","baseline","report","correspondence","transmittal","action item","issue","drawing","document control","quality","safety","risk"],
  highPerms:["edit","modify","update","create","add","submit","export"],
  sodPairs:[
    {a:["create","add","submit","enter"],b:["approve","authorize","post"],l:"Create + Approve"},
    {a:["create","add"],b:["delete"],l:"Create + Delete"},
    {a:["edit","modify"],b:["approve","authorize"],l:"Edit + Approve"},
  ],
};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// ORACLE FUSION ACCESS REVIEW ENGINE — v3
//
// Two changes from the previous build, per explicit feedback:
//
// 1. BASE RISK NOW FOLLOWS THE PRIORITY MATRIX ONLY. A user's risk is the
//    highest priority tier (Critical/High/Medium/Low) actually matched
//    against the curated library — nothing else raises it, except the
//    precise multi-privilege combinations below.
//
// 2. "Procurement Risk" and "Admin-Equivalent" are no longer triggered by
//    holding a single privilege tagged with that category. They now require
//    a genuine COMBINATION of specific access types, exactly as specified:
//
//    Procurement Risk = ALL FOUR of:
//      (a) amend supplier master data
//      (b) supplier bank account access
//      (c) payment configuration access
//      (d) payment method access
//
//    Admin-Equivalent = EITHER:
//      Condition A — ALL THREE of: edit user profiles, user bank account
//        access, and maintain security privileges
//      Condition B — BOTH of: maintain/manage security profiles, and
//        manage user roles
//
// Category tags elsewhere (Direct Admin, Privileged Role, Payroll Risk,
// Reporting/BI Access, Integration/Service Access) remain informational —
// their own Critical/High/Medium/Low priority already reflects severity.
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
const OR_CONFIG={
  SERVICE_ACCOUNT_PATTERNS:["svc","service","bot","integration","oracleint","api","rpa"],
  GENERIC_PATTERNS:["admin","support","test","uat","generic","shared","svc","service","bot","train","demo","sample"],
  ROLE_EXPLOSION_THRESHOLD:25,
};

// ── Precise privilege groups used ONLY for the two combination tests above.
// Each list is matched by EXACT privilege name against the curated library. ──
const OR_COMBO_GROUPS={
  supplierMaster:["Manage Supplier","Maintain Supplier","Maintain Supplier Master Data"],
  supplierBank:["Delete Supplier Bank Account","Edit Supplier Registration Bank Account","Maintain Supplier Bank Accounts","Manage Supplier Bank Account","Manage Supplier Bank Accounts","Update Supplier Bank Account"],
  paymentConfig:["Manage Payment Configuration","Manage Payment Formats","Manage Payment Process Profile","Manage Payment Process Profiles","Manage Payment System","Manage Disbursement Payment Method"],
  paymentMethod:["Manage Payment Methods","Delete Payment Method","Manage Payment Method Defaulting Rule"],
  userProfile:["Edit User","Edit User Roles","Manage User Account","Manage User Accounts","Manage User Details","Manage Users","Manage User Provisioning","Manage User Role Provisioning"],
  userBankAccount:["Manage Bank Account","Manage Bank Account Approvals","Manage Bank Account Security","Manage Bank Account Transfer Security","Manage Bank","Update Bank","Maintain Banks","Maintain Bank Account Transfer","Update Bank Account"],
  securityPrivileges:["Manage Privileges","Manage Function Security","Manage Security Configuration","Manage Security Console","Manage Data Security","Manage Data Security Grants","Manage Data Security Policies","Manage Authentication Policies","Manage Audit Policies","Manage Application Security","Manage Application Role","Manage Duty Roles","Manage Identity Domain","Manage Identity Domains","Manage Identity Roles","FND_MANAGE_AUDIT_POLICIES_PRIV","Edit Access Controls"],
  securityProfiles:["Manage Security Profiles","Maintain Security Profiles","Manage Data Security Profiles","Delete Security Profile"],
  userRoles:["Manage User Roles","Manage Roles","Manage Security Roles","Manage Job Roles","Manage Role Hierarchy","Manage Role Provisioning","Manage Role Delegations","Mass Edit Security Assignments","Manage Groups","Delete Role Hierarchy","Edit Role Hierarchy","Maintain Role Inheritance","Update Role Hierarchy"],
};
// convert each group to a Set for O(1) membership checks
Object.keys(OR_COMBO_GROUPS).forEach(k=>{OR_COMBO_GROUPS[k]=new Set(OR_COMBO_GROUPS[k]);});

// Given a user's per-role privilege breakdown (roleBreakdown: one entry per
// role assigned to that user, each carrying the curated privileges THAT
// SPECIFIC ROLE grants) and a list of specific privilege names responsible
// for a finding, return only the role(s) that actually granted at least one
// of those privileges — never the user's full role list. This is what makes
// "Role" columns precise: a user with 5 assigned roles where only 2 of them
// contain the privilege(s) behind a given finding will show only those 2
// roles, not all 5.
function rolesGranting(roleBreakdown,privilegeNames){
  const wanted=new Set(privilegeNames);
  const roles=[];
  (roleBreakdown||[]).forEach(rb=>{
    if(rb.privileges.some(e=>wanted.has(e.n)))roles.push(rb.role);
  });
  return roles;
}

function isORGenericAccount(userid){
  const v=String(userid||"").split("@")[0];
  return matchesAnyKeyword(v,OR_CONFIG.GENERIC_PATTERNS);
}
function isORServiceAccount(userid){
  const v=String(userid||"").split("@")[0];
  return matchesAnyKeyword(v,OR_CONFIG.SERVICE_ACCOUNT_PATTERNS);
}
function detectRoleExplosion(users){
  const byUser={};
  users.forEach(u=>{if(!byUser[u.user])byUser[u.user]=new Set();byUser[u.user].add((u.roleDisplay||u.role||"").toLowerCase());});
  const findings=[];
  Object.entries(byUser).forEach(([user,set])=>{
    if(set.size>OR_CONFIG.ROLE_EXPLOSION_THRESHOLD)findings.push({userid:user,roleCount:set.size,severity:"High",finding:"Role Explosion"});
  });
  return findings;
}
function orDiagnostic(pu){
  // Explains, in plain terms, exactly why the Privileges column is empty
  // (when it is) — so an empty cell is never a mystery. Distinguishes a
  // genuine "no risk-relevant privilege held" result from a "role name
  // didn't match between your two uploaded files" data problem.
  if(pu.matched.length>0)return "";
  if(pu.rolesWithNoMapping&&pu.rolesWithNoMapping.length>0){
    return `No entry found in Role-to-Privilege file for role(s): ${pu.rolesWithNoMapping.join(", ")} — check the role name matches exactly between your two uploaded files.`;
  }
  if(pu.rawPrivileges&&pu.rawPrivileges.length>0){
    return `Account holds ${pu.rawPrivileges.length} real privilege(s) via its role(s), but none match the 176-entry curated risk library — e.g. ${pu.rawPrivileges.slice(0,3).join(", ")}${pu.rawPrivileges.length>3?"…":""}.`;
  }
  return "No privileges found for this account's role(s) in the Role-to-Privilege file.";
}
function detectORServiceAccounts(perUser,userDeptMap,privilegedSet){
  const findings=[];
  Object.entries(perUser).forEach(([uName,pu])=>{
    if(!isORServiceAccount(uName))return;
    // Show every curated privilege this account holds, at any priority tier
    // (Critical/High/Medium/Low) — not just Critical/High. If none of this
    // account's real privileges match the curated library, this is left
    // empty on purpose: it means no risk-relevant privilege was found for
    // this account, which is itself accurate information, not a data gap.
    // The Diagnostic field explains exactly why, when it's empty.
    const privilegesOut=pu.matched.map(e=>e.n);
    findings.push({
      userid:uName,
      role:pu.roles.join(", "),
      privileges:privilegesOut,
      diagnostic:orDiagnostic(pu),
      group:userDeptMap[uName]||"",
      severity:privilegedSet.has(uName)?"Critical":"High",
      finding:"Service Account"
    });
  });
  return findings;
}
function detectORGenericAccounts(perUser,userDeptMap,privilegedSet){
  const findings=[];
  Object.entries(perUser).forEach(([uName,pu])=>{
    if(!isORGenericAccount(uName))return;
    // Same reasoning as detectORServiceAccounts above.
    const privilegesOut=pu.matched.map(e=>e.n);
    findings.push({
      userid:uName,
      role:pu.roles.join(", "),
      privileges:privilegesOut,
      diagnostic:orDiagnostic(pu),
      group:userDeptMap[uName]||"",
      severity:privilegedSet.has(uName)?"Critical":"High",
      finding:"Generic / Shared Account"
    });
  });
  return findings;
}
function detectDormantPowerfulAccount(perUser,userDeptMap,privilegedSet){
  const findings=[];
  Object.entries(perUser).forEach(([uName,pu])=>{
    if(!privilegedSet.has(uName))return;
    if(isORGenericAccount(uName)||isORServiceAccount(uName)||/integration/i.test(uName)){
      // This finding REQUIRES the account to already hold a Critical/High
      // privilege (privilegedSet gate above), so the role attribution stays
      // scoped to the role(s) that granted those specific Critical/High
      // privileges — but the displayed Privileges list shows every matched
      // privilege at any tier for full context, consistent with E and F.
      const critHighMatches=pu.matched.filter(e=>e.p==="Critical"||e.p==="High");
      const critHighNames=critHighMatches.map(e=>e.n);
      const allMatchNames=pu.matched.map(e=>e.n);
      findings.push({
        userid:uName,
        role:rolesGranting(pu.roleBreakdown,critHighNames).join(", "),
        privileges:allMatchNames,
        group:userDeptMap[uName]||"",
        severity:"High",
        finding:"Dormant / Unattributable Powerful Account"
      });
    }
  });
  return findings;
}
function buildORExecutiveSummary(userRoleData,rolePrivilegeData,data){
  return{
    totalUsers:new Set(userRoleData.map(u=>u.user)).size,
    totalRoles:new Set(userRoleData.map(u=>(u.roleDisplay||u.role||"").toLowerCase())).size,
    totalPrivileges:new Set(rolePrivilegeData.map(r=>r.privilege)).size,
    privilegedUsers:data.privilegedUsers.length,
    adminEquivalentUsers:data.adminEquivalentUsers.length,
    sodViolations:data.sodConflicts.length,
    payrollRisks:data.payrollRisks.length,
    apRisks:data.paymentRisks.length,
    procurementRisks:data.procurementRisks.length,
    serviceAccounts:data.serviceAccounts.length,
    genericAccounts:data.genericAccounts.length,
    excessiveRoleUsers:data.excessiveRoleUsers.length,
    sensitivePrivilegeHolders:data.sensitivePrivileges.length,
  };
}
function buildORAuditFindings(result){
  const list=[];
  if(result.multiSoD&&result.multiSoD.length)list.push(generateFinding("Multi-Privilege SoD Conflict (End-to-End Access)","Critical",result.multiSoD,"This account spans 3 or more distinct risk domains simultaneously (Direct Admin, Admin-Equivalent, Procurement Risk, Payables Risk, Payroll Risk) — effectively unconstrained end-to-end access. Split duties across separate accounts immediately.","A single account able to act across security administration, financial/procurement transactions and payroll simultaneously has no meaningful segregation of duties left — this is the highest-severity access pattern this engine detects."));
  if(result.adminUsers.length)list.push(generateFinding("Direct Administrator Access (Direct Admin category, Critical/High)","Critical",result.adminUsers,"Recertify all users holding a Critical/High privilege categorized Direct Admin; reduce standing population and split security, configuration and implementation duties.","Full administrative capability across the Oracle Fusion instance — user, role and security configuration management. Direct Admin privileges are scoped strictly to system/configuration, workflow, user and security-configuration items (see the Combination Rules sheet) — payment-related privileges are never part of this category."));
  if(result.adminEquivalentUsers.length)list.push(generateFinding("Admin-Equivalent Access (Combination Match)","Critical",result.adminEquivalentUsers,"This is a precise multi-privilege combination match — either (edit user profiles + user bank account + maintain security privileges) or (maintain/manage security profiles + manage user roles). Split these duties across separate accounts.","A single account holding this exact combination can both alter user identities/security configuration and change financial disbursement routing, or can both define security profiles and grant itself/others roles — genuine admin-equivalent capability."));
  if(result.procurementRisks.length)list.push(generateFinding("Procurement Risk (Combination Match)","Critical",result.procurementRisks,"This is a precise 4-way combination match — supplier master data + supplier bank account + payment configuration + payment method, all held by the same account. Segregate these duties across different users.","A single account holding all four can create/amend a supplier, redirect its bank account, and control the payment configuration and method used to pay it — a complete end-to-end disbursement fraud pathway."));
  if(result.genericAccounts.length)list.push(generateFinding("Generic / Shared Account","Critical",result.genericAccounts.map(u=>u.userid),"Replace with named, individually attributable accounts; vault any credential that must remain shared as break-glass only.","Actions cannot be attributed to one person; password sharing and accountability risk."));
  if(result.serviceAccounts.length)list.push(generateFinding("Service / Integration Account","High",result.serviceAccounts.map(u=>u.userid),"Restrict service/integration accounts to least-privilege, non-interactive scopes; vault and auto-rotate credentials.","Compromise of a service credential could allow modification of security configuration or financial records via API/integration."));
  if(result.dormantPowerfulAccounts&&result.dormantPowerfulAccounts.length)list.push(generateFinding("Dormant / Unattributable Powerful Account","High",result.dormantPowerfulAccounts.map(u=>u.userid),"Confirm an accountable human owner for each privileged generic/service/integration account, or disable if unused; obtain last-login data to fully test dormancy.","Privileged access held by an account that cannot be clearly attributed to an individual owner in the extract provided."));
  if(result.paymentRisks.length)list.push(generateFinding("Payables Risk (Manage Invoices + Manage Payments)","Critical",result.paymentRisks,"Separate invoice management from payment management; this is Oracle's own documented AP SoD conflict (Accounts Payable Supervisor).","A single user holding both Manage Payables Invoices and Manage Payables Payments can prepare and disburse a payment end-to-end unilaterally."));
  if(result.payrollRisks.length)list.push(generateFinding("Payroll Risk (2+ Payroll-Risk Privileges)","Critical",result.payrollRisks,"Separate payroll administration/setup from payment/disbursement-related privileges.","A single user holding 2 or more Payroll-Risk-categorized privileges can process and disburse payroll unilaterally."));
  if(result.excessiveRoleUsers.length)list.push(generateFinding("Role Explosion","High",result.excessiveRoleUsers.map(u=>u.userid),"Review users with an unusually high role count for role-design or provisioning-process issues; consolidate overlapping roles.",`User holds more than the configured role-count threshold (${OR_CONFIG.ROLE_EXPLOSION_THRESHOLD}), making effective access very difficult to review manually.`));
  return list;
}



let orgDomainAuto=null;


function analysePM(usersRaw,matrix,adminSheet,options){
  options = options || {};
  _internalAuto = !!options.internalAuto;
  const uh=Object.keys(usersRaw[0]||{});
  const cID=col(uh,["id","user id","userid","username","user","login","email"])||uh[0];
  const cName=col(uh,["first name","last name","full name","display name","employee name","name"]);
  const cLic=col(uh,["license","licence","license type","type"]);
  const cGrp=col(uh,["security group","security template","access group","group name","template name","group","template","role name","role","grp"]);
  let groupColumnMissing=!cGrp;
  const cInact=col(uh,["inactive","status","active","enabled"]);

  const allCount=usersRaw.length;
  const inactiveCount=cInact?usersRaw.filter(u=>{const v=String(u[cInact]||"").toLowerCase().trim();return["yes","true","1","inactive","disabled","x"].includes(v);}).length:null;
  const activeRaw=usersRaw.filter(u=>{if(!cInact)return true;const v=String(u[cInact]||"").toLowerCase().trim();return!["yes","true","1","inactive","disabled","x"].includes(v);});
  const blankGroupCount=cGrp?activeRaw.filter(u=>!String(u[cGrp]||"").trim()).length:activeRaw.length;

  const freq={};activeRaw.forEach(u=>{const d=getDomain(u[cID]);if(d)freq[d]=(freq[d]||0)+1;});
  orgDomainAuto=Object.entries(freq).sort((a,b)=>b[1]-a[1])[0]?.[0]||null;

  const domTxt=(options.approvedDomains||[]).map(s=>String(s).trim().toLowerCase()).filter(Boolean);
  if(domTxt.length)PM_CONFIG.APPROVED_DOMAINS=domTxt;
  const thr=parseInt(options.adminScoreThreshold,10);
  PM_CONFIG.ADMIN_SCORE_THRESHOLD=isNaN(thr)?100:thr;

  const userAccessData=activeRaw.map(u=>({
    id:String(u[cID]||"Unknown").trim(),
    name:cName?String(u[cName]||"").trim():"",
    license:cLic?String(u[cLic]||"").trim():"",
    group:String(u[cGrp]||"").trim()
  }));

  const groupAccessFlat=[];
  const gMap={};
  const gMapDisplay={};
  const formTypeByForm={}; // form (lowercased) -> "System" | "Custom" | ""
  const superNormIndex={}; // superNorm(rawGroupName) -> Set of normText keys — fuzzy fallback for group matching
  const sheetStats={}; // sheetName -> {type, forms:Set} — for the tab-classification diagnostic
  const formColumnsDetected=new Set(); // for the diagnostic — every header actually used as "the form name" across all rows
  if(matrix&&matrix.length){
    const allKeys=new Set();
    matrix.forEach(row=>Object.keys(row).forEach(k=>allKeys.add(k)));
    // Real-world Group Access Matrix exports commonly have a serial-number
    // column ("SI. No", "Sr. No", "S.No", "#") before the actual form-name
    // column — and the form-name column's header can differ BETWEEN tabs
    // (e.g. "Form Name" on the System tab, "Custom Forms" on the Custom
    // tab). Treating "the first column" as the form name (as earlier
    // versions did) silently extracts serial numbers instead of form
    // names, and misclassifies the real form-name column of the OTHER tab
    // as a bogus group. Both are detected here, per header text, not by
    // position — and detection happens PER ROW below (not once globally)
    // so each tab's own form-name column is used correctly regardless of
    // what the other tab calls it.
    const FORM_COL_CANDIDATES=["form name","custom forms","system forms","forms","form","module name","module","screen name","screen"];
    const SN_EXACT=["#","no","sn","sl"];
    const SN_SUBSTR=["si.no","si no","si. no","s.no","s no","s. no","sr.no","sr no","sr. no","sl.no","sl no","sl. no","serial no","serial number","srl no"];
    const hlKey=k=>String(k||"").toLowerCase().trim();
    const isFormLikeHeader=k=>FORM_COL_CANDIDATES.some(c=>hlKey(k).includes(c));
    const isSNLikeHeader=k=>{const h=hlKey(k);return SN_EXACT.includes(h)||SN_SUBSTR.some(c=>h.includes(c));};
    function detectRowFormKey(rowKeys){
      for(const c of FORM_COL_CANDIDATES){
        const found=rowKeys.find(k=>k!=="__sheet"&&hlKey(k).includes(c));
        if(found)return found;
      }
      // Fallback: first column that isn't __sheet/__EMPTY/blank and doesn't
      // look like a serial-number column.
      return rowKeys.find(k=>k!=="__sheet"&&!/^__EMPTY/i.test(String(k))&&hlKey(k)!==""&&!isSNLikeHeader(k))||null;
    }
    // Group columns are anything that isn't __sheet/__EMPTY/blank, isn't a
    // form-name-like header (on ANY tab), and isn't a serial-number column.
    const gCols=[...allKeys].filter(k=>k!=="__sheet"&&!/^__EMPTY/i.test(k)&&k.trim()!==""&&!isFormLikeHeader(k)&&!isSNLikeHeader(k));
    gCols.forEach(g=>{gMap[normText(g)]=[];gMapDisplay[normText(g)]=[];});
    // Fuzzy fallback index: superNorm(rawGroupName) -> [normText keys].
    // Used only when a user's Group value doesn't exact-match any matrix
    // column — if exactly one matrix column shares the same superNorm, it's
    // treated as a confident fuzzy match; if 2+ share it, that's ambiguous
    // and surfaced in the diagnostic rather than guessed.
    gCols.forEach(g=>{
      const sn=superNorm(g);
      const nt=normText(g);
      if(!superNormIndex[sn])superNormIndex[sn]=new Set();
      superNormIndex[sn].add(nt);
    });
    matrix.forEach(row=>{
      const rowKeys=Object.keys(row);
      const formKey=detectRowFormKey(rowKeys);
      if(!formKey)return;
      formColumnsDetected.add(formKey);
      const form=String(row[formKey]||"").trim();
      if(!form)return;
      const sheetName=String(row.__sheet||"(single sheet / CSV — no tab name available)");
      const formType=/custom/i.test(sheetName)?"Custom":/system/i.test(sheetName)?"System":"";
      if(formType)formTypeByForm[form.toLowerCase()]=formType;
      if(!sheetStats[sheetName])sheetStats[sheetName]={type:formType||"Unclassified",forms:new Set()};
      sheetStats[sheetName].forms.add(form);
      gCols.forEach(g=>{
        const perm=String(row[g]||"").trim();
        if(perm&&!["","0","none","-","no access","n/a","no","false"].includes(perm.toLowerCase())){
          groupAccessFlat.push({group:g.trim(),form,permission:perm});
          const gk=normText(g);
          if(!gMap[gk])gMap[gk]=[];
          gMap[gk].push({form:form.toLowerCase(),perm:perm.toLowerCase()});
          if(!gMapDisplay[gk])gMapDisplay[gk]=[];
          gMapDisplay[gk].push({form,perm,formType});
        }
      });
    });
  }

  // Resolves a raw Group value (from the User Access Report) to the matrix
  // column key that should be used to look up that user's effective access.
  // Tries an exact (whitespace-normalized) match first; if that fails,
  // falls back to the aggressive superNorm match — but only commits to it
  // when exactly one matrix column shares that superNorm, so two genuinely
  // different groups that happen to look similar are never silently merged.
  function resolveGroupKey(rawGroup){
    const nt=normText(rawGroup);
    if(gMap[nt]!==undefined)return{key:nt,type:"exact"};
    if(!rawGroup)return{key:null,type:"empty"};
    const sn=superNorm(rawGroup);
    const candidates=superNormIndex[sn]?[...superNormIndex[sn]]:[];
    if(candidates.length===1)return{key:candidates[0],type:"fuzzy"};
    if(candidates.length>1)return{key:null,type:"ambiguous",candidates};
    return{key:null,type:"unmatched"};
  }

  // ── Diagnostic: does every group used in the User Access Report actually
  // resolve to a column in the Group Access Matrix (exactly or via the
  // fuzzy fallback)? A silent mismatch here is the single most common
  // reason a user with real Full Control access ends up with ZERO
  // effective-access rows — this makes that visible instead of a quiet
  // empty result, and shows exactly which resolution path each group took. ──
  const matrixGroupsDisplay=Object.keys(gMap).length?matrix.flatMap(row=>Object.keys(row)).filter((k,i,arr)=>arr.indexOf(k)===i&&k!=="__sheet"&&!/^__EMPTY/i.test(k)&&k.trim()!==""&&gMap[normText(k)]!==undefined):[];
  const reportGroupsDisplay={};
  const groupUserCounts={};
  userAccessData.forEach(u=>{
    if(!u.group)return;
    const n=normText(u.group);
    if(!reportGroupsDisplay[n])reportGroupsDisplay[n]=u.group;
    groupUserCounts[n]=(groupUserCounts[n]||0)+1;
  });
  let exactGroupCount=0;
  const fuzzyGroups=[],ambiguousGroups=[],unmatchedGroups=[];
  Object.entries(reportGroupsDisplay).forEach(([n,display])=>{
    const r=resolveGroupKey(display);
    const entry={group:display,users:groupUserCounts[n]||0};
    if(r.type==="exact")exactGroupCount++;
    else if(r.type==="fuzzy"){entry.matchedTo=r.key;fuzzyGroups.push(entry);}
    else if(r.type==="ambiguous"){entry.candidates=r.candidates;ambiguousGroups.push(entry);}
    else if(r.type==="unmatched")unmatchedGroups.push(entry);
  });
  fuzzyGroups.sort((a,b)=>b.users-a.users);
  ambiguousGroups.sort((a,b)=>b.users-a.users);
  unmatchedGroups.sort((a,b)=>b.users-a.users);
  const totalDistinctReportGroups=Object.keys(reportGroupsDisplay).length;
  const matchedGroupCount=exactGroupCount+fuzzyGroups.length;

  const permFreqMap={};
  groupAccessFlat.forEach(r=>{
    const key=String(r.permission||"").replace(/\u00A0/g," ").replace(/\s+/g," ").trim();
    if(!key)return;
    permFreqMap[key]=(permFreqMap[key]||0)+1;
  });
  const permFreq=Object.entries(permFreqMap).sort((a,b)=>b[1]-a[1]);
  const fullControlCellCount=permFreq.filter(([k])=>/full[\s\-_]*control|full[\s\-_]*access|all[\s\-_]*access|administrator/i.test(k)).reduce((s,[,v])=>s+v,0);

  let pmDiagnostic={
    formColumn:formColumnsDetected.size?[...formColumnsDetected].join(", "):"(no matrix uploaded)",
    matrixGroupCount:matrixGroupsDisplay.length,
    matrixGroupsSample:matrixGroupsDisplay.slice(0,25),
    totalDistinctReportGroups,matchedGroupCount,exactGroupCount,
    fuzzyGroups,ambiguousGroups,unmatchedGroups,
    permFreq,fullControlCellCount,
    matrixRowCount:matrix?matrix.length:0,
    sheets:Object.entries(sheetStats).map(([name,s])=>({name,type:s.type,formCount:s.forms.size}))
  };

  let estEffectiveRows=0;
  for(let i=0;i<userAccessData.length;i++){
    estEffectiveRows+=(gMap[normText(userAccessData[i].group)]||[]).length;
  }
  if(estEffectiveRows>2000000){
    toast(`Large dataset: ~${estEffectiveRows.toLocaleString()} effective-access rows implied by ${userAccessData.length.toLocaleString()} users × the group matrix. This can take up to a minute and use significant browser memory — narrowing the Group Access Matrix to only the groups actually in use will speed this up.`,false);
  }

  let pmAssessment=runPMWebAssessment(userAccessData,groupAccessFlat);
  const adminEquivGroupSet=new Set(pmAssessment.adminEquivalentGroups.map(g=>normText(g.group)));
  const adminUserSet=new Set(pmAssessment.adminUsers.map(u=>u.userid));
  const adminByNameSet=new Set(pmAssessment.adminUsers.filter(u=>u.finding==="Direct Administrator").map(u=>u.userid));
  const avgAdminSet=new Set((pmAssessment.adminByAverageAccess||[]).map(u=>u.userid));
  const avgAdminScoreMap={};
  (pmAssessment.adminByAverageAccess||[]).forEach(u=>{avgAdminScoreMap[normText(u.group)]=u.avgScore;});
  const genericSet=new Set(pmAssessment.genericAccounts.map(u=>u.userid));
  const svcMap={};pmAssessment.serviceAccounts.forEach(u=>svcMap[u.userid]=u.severity);
  const extSet=new Set(pmAssessment.externalUsers.map(u=>u.userid));
  const testSet=new Set(pmAssessment.testAccounts.map(u=>u.userid));
  const sodMap={};pmAssessment.sodConflicts.forEach(f=>sodMap[f.userid]=f.modules);
  const contractorSet=new Set(pmAssessment.contractorAccess.map(f=>f.userid));

  const credShareMap={};const credEntries=[];
  if(adminSheet&&adminSheet.length){
    const ah=Object.keys(adminSheet[0]);
    const cCred=col(ah,["admin credential","credential","account","admin account"])||ah[0];
    const cPersons=col(ah,["persons","persons with access","users","access"])||ah[1];
    adminSheet.forEach(row=>{
      const cred=String(row[cCred]||"").trim();
      const personsRaw=String(row[cPersons]||"");
      if(!cred)return;
      const persons=personsRaw.split(/[;,]/).map(p=>p.trim()).filter(Boolean);
      credEntries.push({cred,persons});
      persons.forEach(p=>{const k=p.toLowerCase();if(!credShareMap[k])credShareMap[k]=[];credShareMap[k].push(cred);});
    });
  }

  const groupAnalysisCache=new Map();
  function analyseGroup(gk,accs){
    if(groupAnalysisCache.has(gk))return groupAnalysisCache.get(gk);
    const allTxt=(gk+" "+accs.map(a=>a.form+" "+a.perm).join(" ")).toLowerCase();
    const critForms=accs.filter(a=>PM_LIB.critForms.some(f=>a.form.includes(f))&&PM_LIB.critPerms.some(p=>a.perm.includes(p)));
    const highForms=accs.filter(a=>(PM_LIB.critForms.some(f=>a.form.includes(f))||PM_LIB.highForms.some(f=>a.form.includes(f)))&&PM_LIB.highPerms.some(p=>a.perm.includes(p)));
    const sodHitsLegacy=[];
    PM_LIB.sodPairs.forEach(pair=>{if(pair.a.some(k=>allTxt.includes(k))&&pair.b.some(k=>allTxt.includes(k)))sodHitsLegacy.push(pair.l);});
    const out={critForms,highForms,sodHitsLegacy};
    groupAnalysisCache.set(gk,out);
    return out;
  }

  const res=[];
  activeRaw.forEach(uRow=>{
    const uidRaw=String(uRow[cID]||"Unknown").trim();
    const grpRaw=String(uRow[cGrp]||"").trim();
    const lic=cLic?String(uRow[cLic]||"").trim():"";
    const gk=(resolveGroupKey(grpRaw).key)||normText(grpRaw);
    const accs=gMap[gk]||[];

    const critGrp=adminUserSet.has(uidRaw);
    const isAdminEquivGroup=adminEquivGroupSet.has(gk)&&!critGrp;
    const {critForms,highForms,sodHitsLegacy}=analyseGroup(gk,accs);
    const scoredSodModules=sodMap[uidRaw]||null;
    const sodHits=scoredSodModules?[`Financial SoD (${scoredSodModules.length} modules: ${scoredSodModules.slice(0,3).join(", ")}${scoredSodModules.length>3?"…":""})`,...sodHitsLegacy]:sodHitsLegacy;

    const isExternal=extSet.has(uidRaw);
    const isGeneric=genericSet.has(uidRaw);
    const isService=svcMap.hasOwnProperty(uidRaw);
    const serviceSeverity=svcMap[uidRaw];
    const isTestAcc=testSet.has(uidRaw);
    const contractorInvoiceAccess=contractorSet.has(uidRaw);
    const guestAdminConflict=PM_CONFIG.LOW_PRIV_LICENCES.some(l=>lic.toLowerCase().includes(l))&&(critGrp||isAdminEquivGroup);
    const sharedCreds=credShareMap[uidRaw.toLowerCase()]||credShareMap[(uidRaw.split("@")[0]||"").toLowerCase()]||[];

    let risk="Safe";
    if(critGrp||sodHits.length||(isGeneric&&(critGrp||isAdminEquivGroup))||sharedCreds.length||(isService&&serviceSeverity==="Critical")||contractorInvoiceAccess||isAdminEquivGroup)risk="Critical";
    else if(guestAdminConflict||critForms.length>=2||(isService&&serviceSeverity==="Medium")||isTestAcc)risk="High";
    else if(critForms.length>=1||highForms.length>=3)risk="High";
    else if(highForms.length>=1||isExternal)risk="Safe";

    const recs=[];
    const isAvgAdmin=avgAdminSet.has(uidRaw)&&!adminByNameSet.has(uidRaw);
    if(critGrp&&adminByNameSet.has(uidRaw))recs.push("Direct administrator (admin-named group) — recertify and reduce standing admin population; split security/config/workflow duties");
    if(isAvgAdmin)recs.push(`Direct administrator by access pattern — this group's average permission score is ${(avgAdminScoreMap[gk]||0).toFixed(1)}/10 (dominated by Create&Edit/Full Control), which is admin-level access regardless of the group's name`);
    if(isAdminEquivGroup)recs.push(`Group scores ≥${PM_CONFIG.ADMIN_SCORE_THRESHOLD} on weighted critical-module access — classify as admin-equivalent despite non-admin name`);
    if(isGeneric&&(critGrp||isAdminEquivGroup))recs.push("Generic/shared account with admin-equivalent access — replace with named, individually attributable accounts");
    if(sharedCreds.length)recs.push(`Recorded access to shared credential(s): ${sharedCreds.join(", ")} — vault as break-glass, remove routine sharing`);
    if(isService)recs.push(serviceSeverity==="Critical"?"Privileged service/bot account with critical-module access — least-privilege, non-interactive, vaulted credentials":"Service/reporting account — confirm read-only scope is sufficient");
    if(contractorInvoiceAccess)recs.push("External contractor can edit Progress Invoices — restrict to draft/submit only, remove certify/approve/post rights");
    if(guestAdminConflict)recs.push("Guest/low-privilege licence assigned to a privileged group — validate business need");
    if(sodHits.length)recs.push("SoD conflict — separate creation, approval and posting rights across different users");
    if(isTestAcc)recs.push("Test/UAT/training account — disable or apply automatic expiry unless an approved testing window is active");
    if(critForms.length&&!critGrp&&!isAdminEquivGroup)recs.push(`Critical/elevated permission on: ${critForms.slice(0,6).map(a=>a.form).join(", ")}${critForms.length>6?` (+${critForms.length-6} more)`:""} — confirm justification`);
    if(!recs.length)recs.push(!grpRaw?"No group assigned in matrix — verify via Project Users/Conditional Security before treating as no access":"No immediate action required");

    const flags={
      priv:critGrp?["Admin/Full group"]:critForms.slice(0,3).map(a=>`${a.form}:${a.perm}`),
      sod:sodHits.slice(0,3),
      sens:highForms.slice(0,2).map(a=>a.form),
      critCount:critForms.length,highCount:highForms.length,
      external:isExternal,externalDomain:getDomain(uidRaw),
      generic:isGeneric,service:isService,serviceSeverity,testAcc:isTestAcc,
      blankGroup:!grpRaw,guestAdmin:guestAdminConflict,
      adminEquivGroup:isAdminEquivGroup,contractorInvoice:contractorInvoiceAccess,
      avgAccessAdmin:isAvgAdmin,avgAccessScore:avgAdminScoreMap[gk]||0,
      sharedCreds
    };
    const formNames=[...new Set((gMapDisplay[gk]||[]).map(a=>a.form))];
    const allPrivileges=(gMapDisplay[gk]||[]).map(a=>`${a.form}: ${a.perm}`);
    const formAccess=(gMapDisplay[gk]||[]).map(a=>({form:a.form,perm:a.perm,formType:a.formType||formTypeByForm[a.form.toLowerCase()]||""}));
    res.push({user:uidRaw,name:cName?String(uRow[cName]||"").trim():"",license:lic,roles:grpRaw,domain:getDomain(uidRaw),forms:formNames,privileges:allPrivileges.slice(0,10),allPrivileges,formAccess,risk,flags,recommendation:recs.join("; ")});
  });

  // ── External User — Privileged Form Access ──────────────────────────
  // Replaces the old "External User Assigned Internal Group" heuristic
  // (which only checked the group's EXT- naming prefix, not actual
  // permission level). This instead runs the real form-level privilege
  // classification and flags any external-domain user who holds Full
  // Control, Privileged (Create+Edit+Delete), or Admin-Equivalent
  // (Edit+Delete) access on at least one form — i.e. rank >= 3 in the
  // same tier system used by the Form-Level Privileged Access panel.
  const pmClassified=buildPMPrivilegedAccessClassification(res);
  const classifiedByUser={};
  pmClassified.forEach(c=>{classifiedByUser[c.user]=c;});
  const externalPrivilegedFindings=[];
  res.forEach(r=>{
    if(!r.flags.external)return;
    const c=classifiedByUser[r.user];
    if(!c||c.highestRank<3)return;
    externalPrivilegedFindings.push({
      userid:r.user,group:r.roles,classification:c.highestTier,
      privileges:c.drivingForms.map(f=>`${f.form} (${f.tier})`),
      severity:"Critical",finding:"External User — Privileged Form Access"
    });
    r.flags.externalPrivileged=true;
    r.flags.externalPrivilegedTier=c.highestTier;
    if(r.risk!=="Critical"){
      r.risk="Critical";
      r.recommendation=`External account holds ${c.highestTier} on: ${c.drivingForms.map(f=>f.form).join(", ")} — restrict to view/create-only or formally justify and time-box; ${r.recommendation}`;
    }
  });
  pmAssessment.externalPrivileged=externalPrivilegedFindings;
  pmAssessment.summary.externalPrivileged=externalPrivilegedFindings.length;
  if(externalPrivilegedFindings.length){
    pmAssessment.narrativeFindings.unshift(generateFinding(
      "External User — Privileged Form Access (Full Control / Edit+Delete)","Critical",
      externalPrivilegedFindings,
      "External/contractor accounts should never hold Full Control, or a combined Edit+Delete, on any form. Restrict to view/create-only access, or formally justify and time-box the elevated grant with a named business sponsor.",
      "An external-domain account holds Full Control, Privileged (Create+Edit+Delete), or Admin-Equivalent (Edit+Delete) access on at least one form — this exceeds what an external party should normally require and is a significant fraud/data-integrity risk if the account is compromised or acting adversarially."
    ));
  }

  // ── Administrator Credentials — Generic/Shared Account with Full Control ──
  // Extends the existing Generic/Shared Account category: specifically
  // flags which generic/shared accounts also hold Full-Control-tier access
  // on any form, since that combination (non-attributable + full control)
  // is the highest-severity accountability risk in this category.
  const sharedFullControlFindings=[];
  res.forEach(r=>{
    if(!r.flags.generic)return;
    const c=classifiedByUser[r.user];
    if(c&&c.highestRank>=5){
      sharedFullControlFindings.push({userid:r.user,group:r.roles,classification:c.highestTier,privileges:c.drivingForms.map(f=>f.form),severity:"Critical"});
      r.flags.sharedFullControl=true;
      if(r.risk!=="Critical")r.risk="Critical";
    }
  });
  pmAssessment.sharedFullControl=sharedFullControlFindings;
  pmAssessment.summary.sharedFullControl=sharedFullControlFindings.length;
  if(sharedFullControlFindings.length){
    pmAssessment.narrativeFindings.splice(1,0,generateFinding(
      "Administrator Credentials — Generic/Shared Account with Full Control","Critical",
      sharedFullControlFindings,
      "Any shared/generic account holding Full Control must be vaulted as break-glass only, with individual checkout, MFA, and post-use review; never used for routine daily work.",
      "A generic or shared account holds Full Control / Administrator-level access on at least one form. Combined with the account being non-attributable to a single individual, this is a critical accountability and non-repudiation risk — actions cannot be traced to a specific person."
    ));
  }
  // Cross-reference: for each shared admin credential recorded in the
  // optional Admin Credentials Sheet (Input 3), flag which named persons
  // with access to it ALSO independently hold Full Control themselves.
  if(credEntries&&credEntries.length){
    credEntries.forEach(e=>{
      e.personsWithFullControl=e.persons.filter(p=>{
        const match=res.find(r=>normText(r.user)===normText(p)||normText(r.user.split("@")[0])===normText(p));
        if(!match)return false;
        const c=classifiedByUser[match.user];
        return c&&c.highestRank>=5;
      });
    });
  }

  // ── External Users — highlight members of admin / admin-equivalent groups ──
  // Keeps the baseline "External User" (Medium) list for full visibility,
  // but separately flags and promotes the subset who are ALSO direct
  // admins or admin-equivalent-group members — a materially higher-risk
  // combination than external domain alone.
  pmAssessment.externalUsers.forEach(u=>{
    const gkForUser=(resolveGroupKey(u.group).key)||normText(u.group);
    u.isAdminGroupMember=adminUserSet.has(u.userid)||adminEquivGroupSet.has(gkForUser);
  });
  const externalAdminGroupUsers=pmAssessment.externalUsers.filter(u=>u.isAdminGroupMember);
  pmAssessment.externalAdminGroupUsers=externalAdminGroupUsers;
  pmAssessment.summary.externalAdminGroupUsers=externalAdminGroupUsers.length;
  if(externalAdminGroupUsers.length){
    pmAssessment.narrativeFindings.splice(1,0,generateFinding(
      "External User in Admin / Admin-Equivalent Group","Critical",
      externalAdminGroupUsers.map(u=>u.userid),
      "External-domain accounts should never be members of an admin or admin-equivalent group. Remove from the privileged group immediately and reissue with a scoped external role.",
      "An external-domain account is a direct or admin-equivalent-scored member of a privileged group — combined with being outside the organization's approved domain(s), this is a critical exposure."
    ));
  }

  // ── Risky Internal Access Rights ────────────────────────────────────
  // (a) Known high-risk PMWeb groups identified in a prior manual review —
  //     any user in one of these groups is flagged at the pre-assessed
  //     severity, regardless of what the generic form-level rules find.
  const KNOWN_RISKY_GROUPS=[
    {pattern:/^damac\s*qs\s*site\s*full$/i,severity:"High",note:"A/P Payments, Commitments, Commitment COs, Cost Ledger, Journal Entries, Progress Invoices"},
    {pattern:/^damac\s*qs\s*site\s*full\s*sp$/i,severity:"High",note:"Similar financial create/edit access"},
    {pattern:/^damac\s*qs\s*site\s*full\s*sp\s*budget$/i,severity:"Critical",note:"Above access plus Budgets and Budget Requests"},
    {pattern:/^project\s*claims\s*&?\s*commer{1,2}cial\s*qs$/i,severity:"High",note:"Broad commercial and financial record access"},
  ];
  const riskyGroupFindings=[];
  res.forEach(r=>{
    const roleText=String(r.roles||"").trim();
    const known=KNOWN_RISKY_GROUPS.find(k=>k.pattern.test(roleText));
    if(known){
      riskyGroupFindings.push({userid:r.user,role:r.roles,group:r.roles,privileges:[known.note],severity:known.severity});
      if(known.severity==="Critical"&&r.risk!=="Critical")r.risk="Critical";
      else if(known.severity==="High"&&r.risk==="Safe")r.risk="High";
    }
  });

  // (b) Procurement L2/L3 roles that can create or edit Commitments or
  //     Commitment Change Orders.
  const procurementCommitmentFindings=[];
  res.forEach(r=>{
    if(!/procurement\s*l[23]|procl[23]/i.test(String(r.roles||"")))return;
    const hits=(r.formAccess||[]).filter(f=>/commitment/i.test(f.form)&&parsePMPermissionTier(f.perm).rank>=2);
    if(hits.length){
      procurementCommitmentFindings.push({userid:r.user,role:r.roles,group:r.roles,privileges:hits.map(f=>`${f.form}: ${f.perm}`),severity:"High"});
      if(r.risk==="Safe")r.risk="High";
    }
  });

  // (c) Project Finance-Team members with Edit access to Progress Invoices.
  const projectFinanceInvoiceFindings=[];
  res.forEach(r=>{
    if(!/project\s*finance[\s\-]*team/i.test(String(r.roles||"")))return;
    const hits=(r.formAccess||[]).filter(f=>/progress\s*invoice/i.test(f.form)&&parsePMPermissionTier(f.perm).rank>=1.5);
    if(hits.length){
      projectFinanceInvoiceFindings.push({userid:r.user,role:r.roles,group:r.roles,privileges:hits.map(f=>`${f.form}: ${f.perm}`),severity:"High"});
      if(r.risk==="Safe")r.risk="High";
    }
  });

  pmAssessment.riskyInternal={
    knownGroups:riskyGroupFindings,
    procurementCommitment:procurementCommitmentFindings,
    projectFinanceInvoice:projectFinanceInvoiceFindings
  };
  const riskyInternalTotal=riskyGroupFindings.length+procurementCommitmentFindings.length+projectFinanceInvoiceFindings.length;
  pmAssessment.summary.riskyInternalTotal=riskyInternalTotal;

  if(riskyGroupFindings.length){
    pmAssessment.narrativeFindings.push(generateFinding(
      "Risky Internal Access — Known High-Risk Group","High",
      riskyGroupFindings,
      "These groups were identified in a prior manual review as holding broad financial/commercial access. Recertify membership and confirm continued business need for each individual.",
      "Membership in these specific PMWeb groups grants broad create/edit access across multiple financial modules (Commitments, Commitment COs, Cost Ledger, Journal Entries, Progress Invoices, and in the Budget-flavoured variant, Budgets/Budget Requests too)."
    ));
  }
  if(procurementCommitmentFindings.length){
    pmAssessment.narrativeFindings.push(generateFinding(
      "Risky Internal Access — Procurement Role with Commitment/CO Access","High",
      procurementCommitmentFindings,
      "Procurement L2/L3 roles that can create or edit Commitments or Commitment Change Orders should be reviewed for segregation from approval/certification duties.",
      "A Procurement L2/L3 user can create or edit Commitments and/or Commitment Change Orders — combined with typical approval workflows, this can enable a single procurement resource to originate and modify high-value contractual commitments unilaterally."
    ));
  }
  if(projectFinanceInvoiceFindings.length){
    pmAssessment.narrativeFindings.push(generateFinding(
      "Risky Internal Access — Project Finance Edit Access to Progress Invoices","High",
      projectFinanceInvoiceFindings,
      "Project Finance-Team members with Edit access to Progress Invoices should be reviewed against certification/approval segregation requirements.",
      "A Project Finance-Team user can edit Progress Invoice (IPC) records — this team is typically expected to review/validate rather than directly edit certified payment certificates."
    ));
  }

  let govNotes={
    orgDomain:options.internalAuto?orgDomainAuto:PM_CONFIG.APPROVED_DOMAINS.join(", "),
    allCount,activeCount:activeRaw.length,inactiveCount,blankGroupCount,
    extCount:pmAssessment.summary.externalUsers,genCount:pmAssessment.summary.genericAccounts,
    testCount:pmAssessment.summary.testAccounts,svcCount:pmAssessment.summary.serviceAccounts,
    adminEquivCount:pmAssessment.adminUsers.length+pmAssessment.adminEquivalentGroups.length,
    avgAccessAdminCount:pmAssessment.summary.adminByAverageAccess,
    sharedCredCount:res.filter(r=>r.flags.sharedCreds.length).length,
    sodCount:pmAssessment.summary.sodConflicts,contractorCount:pmAssessment.summary.contractorAccess,
    adminEquivGroupNames:pmAssessment.adminEquivalentGroups.map(g=>`${g.group} (score ${g.score})`),
    groupColumnMissing,detectedColumns:{id:cID,name:cName,group:cGrp,license:cLic,inactive:cInact},
    credEntries
  };
  return {res, pmAssessment, govNotes, pmDiagnostic};
}



function parsePMPermissionTier(permRaw){
  const p=String(permRaw||"").replace(/\u00A0/g," ").replace(/\s+/g," ").trim();
  if(!p)return{tier:"No Access",rank:0};
  const pl=p.toLowerCase();
  if(["none","-","n/a","no access","no","0","false"].includes(pl))return{tier:"No Access",rank:0};
  const hasFull=/full[\s\-_]*control|full[\s\-_]*access|all[\s\-_]*access|administrator/.test(pl);
  if(hasFull)return{tier:"Full Control / Administrator Access",rank:5};
  const hasCreate=/creat|add|insert/.test(pl);
  const hasEdit=/edit|modify|updat|writ/.test(pl);
  const hasDelete=/delet|remov/.test(pl);
  const hasView=/view|read/.test(pl);
  if(hasCreate&&hasEdit&&hasDelete)return{tier:"Privileged Access",rank:4};
  if(pl==="delete"||(hasEdit&&hasDelete))return{tier:"Admin-Equivalent Access",rank:3};
  if(hasCreate&&hasEdit)return{tier:"Elevated Access (Create + Edit)",rank:2};
  if(hasEdit)return{tier:"Edit Access",rank:1.5};
  if(hasView)return{tier:"View-Only Access",rank:1};
  return{tier:"Other / Unclassified",rank:0.5};
}
function buildPMPrivilegedAccessClassification(results){
  const out=[];
  (results||[]).forEach(r=>{
    const source=(r.formAccess&&r.formAccess.length)?r.formAccess:(r.allPrivileges||[]).map(s=>{
      // Fallback for any caller that only has the flattened string form
      // (e.g. older cached results without formAccess).
      const idx=s.indexOf(": ");
      return{form:idx>=0?s.slice(0,idx):s,perm:idx>=0?s.slice(idx+2):"",formType:""};
    });
    const forms=source.map(a=>{
      const t=parsePMPermissionTier(a.perm);
      return{form:a.form,perm:a.perm,formType:a.formType||"",tier:t.tier,rank:t.rank};
    }).filter(f=>f.rank>0);
    if(!forms.length)return;
    const highestRank=Math.max(...forms.map(f=>f.rank));
    const highestTier=forms.find(f=>f.rank===highestRank).tier;
    const drivingForms=forms.filter(f=>f.rank===highestRank);
    const criticalFormsRaw=forms.filter(f=>f.rank>=3&&moduleIsFinancial(f.form));
    const criticalForms=[...new Map(criticalFormsRaw.map(f=>[f.form.toLowerCase(),f])).values()];
    const combined=criticalForms.length>=2;
    out.push({user:r.user,group:r.roles,highestTier,highestRank,drivingForms,combined,criticalForms,allForms:forms});
  });
  return out;
}


function analyseOR(userRoleRaw,rolePrivRaw,options){
  options = options || {};
  const urH=Object.keys(userRoleRaw[0]||{});
  const cU=col(urH,["user name","username","user","login","email","person","employee"])||urH[0];
  const cDept=col(urH,["department"]);
  const cLoc=col(urH,["location"]);
  const cRDisp=col(urH,["assigned role display name","role display name","display name"]);
  const cR=col(urH,["assigned role name","job role","role name","role","responsibility","group","template","assignment"])||urH[1];
  const cStripe=col(urH,["policy stripe","stripe"]);

  const rpH=Object.keys(rolePrivRaw[0]||{});
  const rpR=col(rpH,["job role name","role name","role","job role","group","responsibility"])||rpH[0];
  const rpP=col(rpH,["privilege name","privilege","duty role","permission","access","function"])||rpH[1];

  const expThr=parseInt(options.roleExplosionThreshold,10);
  OR_CONFIG.ROLE_EXPLOSION_THRESHOLD=isNaN(expThr)?25:expThr;

  if(userRoleRaw.length>300000)toast(`Large file detected (${userRoleRaw.length.toLocaleString()} rows) — de-duplicating repeated user/role rows before analysis, this may take a few seconds.`,false);
  const seenUR=new Set();
  const userRoleData=[];
  for(let i=0;i<userRoleRaw.length;i++){
    const row=userRoleRaw[i];
    const user=String(row[cU]||"Unknown").trim();
    if(!user||user==="Unknown")continue;
    const role=String(row[cR]||"").trim();
    const roleDisplay=cRDisp?String(row[cRDisp]||"").trim():role;
    const key=user+"|"+(roleDisplay||role).toLowerCase();
    if(seenUR.has(key))continue;
    seenUR.add(key);
    userRoleData.push({
      user, dept:cDept?String(row[cDept]||"").trim():"", location:cLoc?String(row[cLoc]||"").trim():"",
      role, roleDisplay, stripe:cStripe?String(row[cStripe]||"").trim():""
    });
  }
  const seenRP=new Set();
  const rolePrivilegeData=[];
  for(let i=0;i<rolePrivRaw.length;i++){
    const row=rolePrivRaw[i];
    const role=String(row[rpR]||"").trim();
    const privilege=String(row[rpP]||"").trim();
    if(!role||!privilege)continue;
    const key=role.toLowerCase()+"|"+privilege.toLowerCase();
    if(seenRP.has(key))continue;
    seenRP.add(key);
    rolePrivilegeData.push({role,privilege});
  }

  // Role -> raw privilege name list (exactly as supplied in the uploaded file)
  const rPMap={};
  rolePrivilegeData.forEach(r=>{
    const rk=r.role.toLowerCase().trim();
    if(!rPMap[rk])rPMap[rk]=[];
    rPMap[rk].push(r.privilege);
  });

  // Role -> matched CURATED library entries — EXACT NAME MATCH ONLY
  const roleMatchCache=new Map();
  function matchesForRole(roleName){
    const rk=String(roleName||"").toLowerCase().trim();
    if(roleMatchCache.has(rk))return roleMatchCache.get(rk);
    const rawPrivs=rPMap[rk]||[];
    const matched=[];
    const seen=new Set();
    rawPrivs.forEach(p=>{
      const e=OR_LIB_INDEX.get(String(p||"").toLowerCase().trim());
      if(e&&!seen.has(e.n)){seen.add(e.n);matched.push(e);}
    });
    roleMatchCache.set(rk,matched);
    return matched;
  }

  // "Privileged Roles" KPI: distinct roles holding >=1 Critical/High curated match
  const distinctRoles=new Set(userRoleData.map(u=>(u.roleDisplay||u.role||"").trim()).filter(Boolean));
  let privilegedRoleCount=0;
  distinctRoles.forEach(rname=>{
    if(matchesForRole(rname).some(e=>e.p==="Critical"||e.p==="High"))privilegedRoleCount++;
  });
  let orRolePrivCounts={privilegedRoleCount,totalDistinctRoles:distinctRoles.size};

  // Group distinct roles per user
  const uMapSet={};
  userRoleData.forEach(u=>{
    if(!uMapSet[u.user])uMapSet[u.user]=new Set();
    const rname=u.roleDisplay||u.role;
    if(rname)uMapSet[u.user].add(rname);
  });
  const uMap={};
  Object.keys(uMapSet).forEach(k=>{uMap[k]=[...uMapSet[k]];});

  // Username-pattern based findings (independent of privilege matching)
  const roleExplosionFindings=detectRoleExplosion(userRoleData);
  const roleExplosionMap={};roleExplosionFindings.forEach(u=>roleExplosionMap[u.userid]=u.roleCount);

  const PRIORITY_RANK={Critical:4,High:3,Medium:2,Low:1};

  // First pass: compute matched privileges + base risk per user, AND a
  // per-role breakdown (which specific role granted which specific curated
  // privilege) — this is what the Excel "Role-Privilege Detail" sheet needs
  // to answer "which roles were given, and through which privilege".
  const perUser={};
  Object.entries(uMap).forEach(([uName,roles])=>{
    const matchMap=new Map();
    const roleBreakdown=[];
    const rawPrivSet=new Set();
    const rolesWithNoMapping=[]; // roles that have ZERO rows in the Role-to-Privilege file at all
    roles.forEach(r=>{
      const m=matchesForRole(r);
      roleBreakdown.push({role:r,privileges:m});
      m.forEach(e=>matchMap.set(e.n,e));
      const rawForRole=rPMap[String(r||"").toLowerCase().trim()]||[];
      if(rawForRole.length===0)rolesWithNoMapping.push(r);
      // Also keep the RAW (unmatched-to-curated-library) privilege names for
      // this user, exactly as supplied in the Role-to-Privilege file — used
      // only for the diagnostic column below, so we can tell "this role has
      // no entry in the Role-to-Privilege file at all" (a data/column-
      // mapping problem between the two uploaded files) apart from "this
      // role has real privileges, none of which are in our curated list"
      // (expected, correct behavior).
      rawForRole.forEach(p=>{ if(p)rawPrivSet.add(p); });
    });
    const matched=[...matchMap.values()];
    let risk="Safe", topRank=0;
    matched.forEach(e=>{ const rk=PRIORITY_RANK[e.p]||0; if(rk>topRank){topRank=rk;risk=e.p;} });
    perUser[uName]={roles,matched,risk,topRank,roleBreakdown,rawPrivileges:[...rawPrivSet],rolesWithNoMapping};
  });

  const privilegedSet=new Set(Object.entries(perUser).filter(([,v])=>v.topRank>=PRIORITY_RANK.High).map(([k])=>k));
  // "Group" column for Generic/Service/Dormant Excel sheets — Oracle has no
  // native "Group" concept like PMWeb, so this uses Department from the
  // User-and-Roles extract (first non-empty value seen per user) as the
  // closest organizational equivalent.
  const userDeptMap={};
  userRoleData.forEach(u=>{ if(u.dept&&!userDeptMap[u.user])userDeptMap[u.user]=u.dept; });
  const genericAccounts=detectORGenericAccounts(perUser,userDeptMap,privilegedSet);
  const genericSet=new Set(genericAccounts.map(u=>u.userid));
  const serviceAccounts=detectORServiceAccounts(perUser,userDeptMap,privilegedSet);
  const svcMap={};serviceAccounts.forEach(u=>svcMap[u.userid]=u.severity);
  const dormantPowerfulAccounts=detectDormantPowerfulAccount(perUser,userDeptMap,privilegedSet);
  const dormantSet=new Set(dormantPowerfulAccounts.map(u=>u.userid));

  // Tracks, per Critical-tier privilege, how many distinct users hold it —
  // this answers "how is it possible so many users show Critical?" directly.
  const criticalDriverCounts=new Map();
  const highDriverCounts=new Map();

  const res=[];
  const procurementRiskFindings=[];
  const payablesRiskFindings=[];
  const payrollRiskFindings=[];
  const adminEquivFindings=[];
  const directAdminFindings=[];
  const multiSoDFindings=[];

  let orDirectAdminTop=null;

  Object.entries(perUser).forEach(([uName,pu])=>{
    const {roles,matched,roleBreakdown}=pu;
    const roleStr=roles.join(", ");
    let risk=pu.risk;
    const matchedNames=new Set(matched.map(e=>e.n));
    const has=(groupKey)=>{ for(const n of OR_COMBO_GROUPS[groupKey]) if(matchedNames.has(n)) return true; return false; };
    const hitNames=(groupKey)=>[...OR_COMBO_GROUPS[groupKey]].filter(n=>matchedNames.has(n));

    matched.forEach(e=>{
      if(e.p==="Critical")criticalDriverCounts.set(e.n,(criticalDriverCounts.get(e.n)||0)+1);
      if(e.p==="High")highDriverCounts.set(e.n,(highDriverCounts.get(e.n)||0)+1);
    });

    // ── Procurement Risk: ALL FOUR groups present ──
    const hasSupplierMaster=has("supplierMaster");
    const hasSupplierBank=has("supplierBank");
    const hasPaymentConfig=has("paymentConfig");
    const hasPaymentMethod=has("paymentMethod");
    const isProcurementCombo=hasSupplierMaster&&hasSupplierBank&&hasPaymentConfig&&hasPaymentMethod;
    const procurementHits=isProcurementCombo?[...hitNames("supplierMaster"),...hitNames("supplierBank"),...hitNames("paymentConfig"),...hitNames("paymentMethod")]:[];

    // ── Admin-Equivalent: Condition A (all 3) OR Condition B (both 2) ──
    const hasUserProfile=has("userProfile");
    const hasUserBankAccount=has("userBankAccount");
    const hasSecurityPrivileges=has("securityPrivileges");
    const conditionA=hasUserProfile&&hasUserBankAccount&&hasSecurityPrivileges;
    const hasSecurityProfiles=has("securityProfiles");
    const hasUserRoles=has("userRoles");
    const conditionB=hasSecurityProfiles&&hasUserRoles;
    const isAdminEquivCombo=conditionA||conditionB;
    const adminEquivHits=isAdminEquivCombo?(conditionA?[...hitNames("userProfile"),...hitNames("userBankAccount"),...hitNames("securityPrivileges")]:[...hitNames("securityProfiles"),...hitNames("userRoles")]):[];

    // ── Payables SoD (precise 2-privilege combo) ──
    const isPayablesSoD=matchedNames.has("Manage Payables Invoices")&&matchedNames.has("Manage Payables Payments");
    // ── Payroll SoD (2+ Payroll Risk category items) ──
    const payrollMatches=matched.filter(e=>e.cat==="Payroll Risk");
    const isPayrollSoD=payrollMatches.length>=2;

    // ── Direct Admin: Critical/High privilege(s) tagged Direct Admin ──
    const directAdminMatches=matched.filter(e=>(e.p==="Critical"||e.p==="High")&&e.cat==="Direct Admin");
    const isDirectAdmin=directAdminMatches.length>0;

    if(isProcurementCombo||isAdminEquivCombo||isPayablesSoD||isPayrollSoD)risk="Critical";

    // ── Multi-Privilege SoD Conflict: end-to-end access spanning 3+ of the
    // distinct risk domains below on a single account. ──
    const domainsHit=[];
    if(isDirectAdmin)domainsHit.push("Direct Admin");
    if(isAdminEquivCombo)domainsHit.push("Admin-Equivalent");
    if(isProcurementCombo)domainsHit.push("Procurement Risk");
    if(isPayrollSoD)domainsHit.push("Payroll Risk");
    if(isPayablesSoD)domainsHit.push("Payables Risk");
    const isMultiSoD=domainsHit.length>=3;
    if(isMultiSoD)risk="Critical";

    // Every finding object below carries a CLEAN userid plus explicit role
    // and privileges columns. "role" is filtered down to ONLY the role(s)
    // that actually granted the specific triggering privilege(s) for THIS
    // finding — not the user's full role list. A user with 5 assigned roles
    // where only 2 of them contain the relevant sensitive privilege(s) will
    // show only those 2 roles here.
    const payablesPrivNames=["Manage Payables Invoices","Manage Payables Payments"];
    const payrollPrivNames=payrollMatches.map(e=>e.n);
    const directAdminPrivNames=directAdminMatches.map(e=>e.n);
    if(isProcurementCombo)procurementRiskFindings.push({userid:uName,role:rolesGranting(roleBreakdown,procurementHits).join(", "),privileges:procurementHits,duties:procurementHits,severity:"Critical",finding:"Procurement Risk (Combination)"});
    if(isAdminEquivCombo)adminEquivFindings.push({userid:uName,role:rolesGranting(roleBreakdown,adminEquivHits).join(", "),privileges:adminEquivHits,severity:"Critical",finding:"Admin-Equivalent (Combination)"});
    if(isPayablesSoD)payablesRiskFindings.push({userid:uName,role:rolesGranting(roleBreakdown,payablesPrivNames).join(", "),privileges:payablesPrivNames,severity:"Critical",finding:"Payables Risk (Invoice + Payment)"});
    if(isPayrollSoD)payrollRiskFindings.push({userid:uName,role:rolesGranting(roleBreakdown,payrollPrivNames).join(", "),privileges:payrollPrivNames,severity:"Critical",finding:"Payroll Risk"});
    if(isDirectAdmin)directAdminFindings.push({userid:uName,role:rolesGranting(roleBreakdown,directAdminPrivNames).join(", "),privileges:directAdminPrivNames,severity:risk,finding:"Direct Admin Access"});
    if(isMultiSoD){
      const multiSoDPrivileges=[...new Set([
        ...directAdminPrivNames,
        ...adminEquivHits,
        ...procurementHits,
        ...payrollPrivNames,
        ...(isPayablesSoD?payablesPrivNames:[])
      ])];
      multiSoDFindings.push({userid:uName,role:rolesGranting(roleBreakdown,multiSoDPrivileges).join(", "),privileges:multiSoDPrivileges,domains:domainsHit,severity:"Critical",finding:"Multi-Privilege SoD Conflict (End-to-End Access)"});
    }

    const isGenericAcc=genericSet.has(uName);
    const isServiceAcc=svcMap.hasOwnProperty(uName);
    const serviceSeverity=svcMap[uName];
    const isDormant=dormantSet.has(uName);
    const roleCount=roleExplosionMap[uName]||null;

    // Generic/service account holding a genuinely Critical-tier privilege is
    // a standalone accountability escalation
    if(isGenericAcc&&pu.topRank>=PRIORITY_RANK.Critical)risk="Critical";

    const recs=[];
    if(isMultiSoD)recs.push(`Multi-Privilege SoD Conflict: end-to-end access spanning ${domainsHit.length} risk domains (${domainsHit.join(", ")}) — this account can act across security, financial and procurement/payroll functions unilaterally. Split immediately.`);
    if(isDirectAdmin)recs.push(`Direct Admin access: holds ${directAdminMatches.length} Critical/High privilege(s) categorized Direct Admin (${directAdminMatches.slice(0,2).map(e=>e.n).join(", ")}) — recertify; restrict to IT Security team`);
    if(isAdminEquivCombo)recs.push(conditionA?"Admin-Equivalent combination: edit user profiles + user bank account + maintain security privileges — segregate these three duties":"Admin-Equivalent combination: maintain/manage security profiles + manage user roles — segregate these two duties");
    if(isProcurementCombo)recs.push("Procurement Risk combination: supplier master + supplier bank account + payment configuration + payment method — segregate these four duties across different users");
    if(isPayablesSoD)recs.push("Payables SoD: holds both Manage Payables Invoices AND Manage Payables Payments — segregate invoice and payment duties");
    if(isPayrollSoD)recs.push(`Payroll SoD: holds ${payrollMatches.length} Payroll-Risk privileges — segregate payroll administration from execution`);
    if(isGenericAcc)recs.push("Generic/shared account naming pattern — replace with named, individually attributable accounts");
    if(isServiceAcc)recs.push(serviceSeverity==="Critical"?"Service/integration account with privileged access — least-privilege, non-interactive, vaulted credentials":"Service/integration account — confirm scope is minimal and necessary");
    if(isDormant)recs.push("Privileged access on a generic/service/integration-named account — confirm an accountable human owner or disable");
    if(roleCount)recs.push(`Role explosion: ${roleCount} distinct roles assigned — review for role-design or provisioning issues`);
    if(matched.some(e=>["FIN","ATR"].includes(e.bp)))recs.push("Financial configuration access — restrict to Finance IT team");
    if(matched.some(e=>e.bp==="INT"))recs.push("Integration/import privileges — restrict and monitor");
    if(!recs.length)recs.push(risk==="Safe"?"No curated high-value privilege matched for this user — routine access":"Review privilege against job need");

    const flags={
      priv:matched.filter(e=>e.p==="Critical"||e.p==="High").slice(0,5).map(e=>`[${e.bp}] ${e.n}`),
      sod:[isPayablesSoD?"Payables Risk":null,isPayrollSoD?"Payroll Risk":null,isProcurementCombo?"Procurement Risk (Combo)":null,isAdminEquivCombo?"Admin-Equivalent (Combo)":null,isMultiSoD?"Multi-Privilege SoD":null].filter(Boolean),
      sens:matched.filter(e=>e.p==="Medium"||e.p==="Low").slice(0,3).map(e=>e.n),
      critCount:matched.filter(e=>e.p==="Critical").length,
      highCount:matched.filter(e=>e.p==="High").length,
      directAdmin:isDirectAdmin,directAdminPrivileges:directAdminMatches.map(e=>e.n),
      privilegedRole:pu.topRank>=PRIORITY_RANK.High,adminEquiv:isAdminEquivCombo,adminEquivMasters:isAdminEquivCombo,adminEquivPrivileges:adminEquivHits,
      generic:isGenericAcc,service:isServiceAcc,serviceSeverity,dormant:isDormant,
      superUser:isMultiSoD,superUserRoles:domainsHit,
      procurementRisk:isProcurementCombo,procurementDuties:procurementHits,
      payablesRisk:isPayablesSoD,payrollRisk:isPayrollSoD,payrollPrivileges:payrollMatches.map(e=>e.n),
      accessCertRisk:false,roleExplosion:!!roleCount,roleCount:roleCount||0,
      sensitivePrivilege:false,multiSoD:isMultiSoD
    };

    const privNames=matched.map(e=>e.n);
    res.push({user:uName,license:"",roles:roleStr,roleBreakdown,privileges:privNames.length?privNames.slice(0,8):roles.slice(0,6),allPrivileges:privNames,domain:"",forms:[],risk,flags,recommendation:recs.slice(0,4).join("; ")});

    if(isDirectAdmin){
      const cnt=directAdminMatches.length;
      if(!orDirectAdminTop||cnt>orDirectAdminTop.count){
        orDirectAdminTop={user:uName,count:cnt};
      }
    }
  });

  const adminEquivUsersDeduped=adminEquivFindings;
  const payablesDeduped=payablesRiskFindings;
  const payrollDeduped=payrollRiskFindings;
  const procurementDeduped=procurementRiskFindings;
  const directAdminDeduped=directAdminFindings;
  const multiSoDDeduped=multiSoDFindings;
  const sodConflicts=[...payablesDeduped,...payrollDeduped,...multiSoDDeduped];

  const criticalDrivers=[...criticalDriverCounts.entries()].sort((a,b)=>b[1]-a[1]).map(([name,count])=>({name,count}));
  const highDrivers=[...highDriverCounts.entries()].sort((a,b)=>b[1]-a[1]).map(([name,count])=>({name,count}));

  let orAssessment={
    adminUsers:directAdminDeduped,
    privilegedUsers:directAdminDeduped,
    excessiveRoleUsers:roleExplosionFindings,
    sodConflicts,
    multiSoD:multiSoDDeduped,
    payrollRisks:payrollDeduped,
    procurementRisks:procurementDeduped,
    paymentRisks:payablesDeduped,
    serviceAccounts,
    adminEquivalentUsers:adminEquivUsersDeduped,
    sensitivePrivileges:[],
    genericAccounts,
    dormantPowerfulAccounts,
    accessCertificationRisks:[],
    superUser:[],
    criticalDrivers,
    highDrivers,
  };
  orAssessment.executiveSummary=buildORExecutiveSummary(userRoleData,rolePrivilegeData,orAssessment);
  orAssessment.narrativeFindings=buildORAuditFindings(orAssessment);

  return {res, orAssessment, orRolePrivCounts, orDirectAdminTop};
}


module.exports = { analysePM, analyseOR, OR_LIB, PM_CONFIG, PM_LIB };
