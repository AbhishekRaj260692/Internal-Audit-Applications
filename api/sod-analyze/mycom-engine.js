// ═══════════════════════════════════════════════════════════════
// MYCOM — SERVER-SIDE RULE ENGINE (110 window-level rules)
// ═══════════════════════════════════════════════════════════════
const MYCOM_CONFLICTS = [
  {"ruleId": "ACC-001", "name": "Supplier Master & Payable Invoice", "priority": "Critical", "cycle": "Finance & Accounts", "area": "Finance & Accounts", "system": "MyCom", "win1": "Supplier Master", "win2": "Payable Invoice", "risk": "User can create supplier and enter invoice for same supplier.", "impact": "SOD violation — Finance & Accounts (MyCom)", "mitigation": "Segregate 'Supplier Master' and 'Payable Invoice' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "ACC-002", "name": "Supplier Master & Payments", "priority": "Critical", "cycle": "Finance & Accounts", "area": "Finance & Accounts", "system": "MyCom", "win1": "Supplier Master", "win2": "Payments", "risk": "User can create supplier and process payments.", "impact": "SOD violation — Finance & Accounts (MyCom)", "mitigation": "Segregate 'Supplier Master' and 'Payments' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "ACC-003", "name": "Supplier Master & Batch Payments", "priority": "Critical", "cycle": "Finance & Accounts", "area": "Finance & Accounts", "system": "MyCom", "win1": "Supplier Master", "win2": "Batch Payments", "risk": "Vendor creation and payment execution by same user.", "impact": "SOD violation — Finance & Accounts (MyCom)", "mitigation": "Segregate 'Supplier Master' and 'Batch Payments' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "ACC-004", "name": "Customer Master & Receivable Invoices", "priority": "Critical", "cycle": "Finance & Accounts", "area": "Finance & Accounts", "system": "MyCom", "win1": "Customer Master", "win2": "Receivable Invoices", "risk": "User can create customer and raise receivable invoices.", "impact": "SOD violation — Finance & Accounts (MyCom)", "mitigation": "Segregate 'Customer Master' and 'Receivable Invoices' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "ACC-005", "name": "Customer Master & Receipts", "priority": "Critical", "cycle": "Finance & Accounts", "area": "Finance & Accounts", "system": "MyCom", "win1": "Customer Master", "win2": "Receipts", "risk": "User can create customer and record collections.", "impact": "SOD violation — Finance & Accounts (MyCom)", "mitigation": "Segregate 'Customer Master' and 'Receipts' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "ACC-006", "name": "Payable Invoice & Payments", "priority": "Critical", "cycle": "Finance & Accounts", "area": "Finance & Accounts", "system": "MyCom", "win1": "Payable Invoice", "win2": "Payments", "risk": "User can create and pay supplier invoices.", "impact": "SOD violation — Finance & Accounts (MyCom)", "mitigation": "Segregate 'Payable Invoice' and 'Payments' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "ACC-007", "name": "Payable Invoice & Batch Payments", "priority": "Critical", "cycle": "Finance & Accounts", "area": "Finance & Accounts", "system": "MyCom", "win1": "Payable Invoice", "win2": "Batch Payments", "risk": "User can create and settle AP liabilities.", "impact": "SOD violation — Finance & Accounts (MyCom)", "mitigation": "Segregate 'Payable Invoice' and 'Batch Payments' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "ACC-008", "name": "Receivable Invoices & Receipts", "priority": "Critical", "cycle": "Finance & Accounts", "area": "Finance & Accounts", "system": "MyCom", "win1": "Receivable Invoices", "win2": "Receipts", "risk": "User can create and settle customer invoices.", "impact": "SOD violation — Finance & Accounts (MyCom)", "mitigation": "Segregate 'Receivable Invoices' and 'Receipts' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "ACC-009", "name": "Payments & Bank Reconciliation - Entry", "priority": "Critical", "cycle": "Finance & Accounts", "area": "Finance & Accounts", "system": "MyCom", "win1": "Payments", "win2": "Bank Reconciliation - Entry", "risk": "User can make payments and reconcile them.", "impact": "SOD violation — Finance & Accounts (MyCom)", "mitigation": "Segregate 'Payments' and 'Bank Reconciliation - Entry' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "ACC-010", "name": "Receipts & Bank Reconciliation - Entry", "priority": "Critical", "cycle": "Finance & Accounts", "area": "Finance & Accounts", "system": "MyCom", "win1": "Receipts", "win2": "Bank Reconciliation - Entry", "risk": "User can receive funds and reconcile own entries.", "impact": "SOD violation — Finance & Accounts (MyCom)", "mitigation": "Segregate 'Receipts' and 'Bank Reconciliation - Entry' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "ACC-011", "name": "Bank Master & Payments", "priority": "Critical", "cycle": "Finance & Accounts", "area": "Finance & Accounts", "system": "MyCom", "win1": "Bank Master", "win2": "Payments", "risk": "User can modify bank details and execute payments.", "impact": "SOD violation — Finance & Accounts (MyCom)", "mitigation": "Segregate 'Bank Master' and 'Payments' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "ACC-012", "name": "Bank Master & Batch Payments", "priority": "Critical", "cycle": "Finance & Accounts", "area": "Finance & Accounts", "system": "MyCom", "win1": "Bank Master", "win2": "Batch Payments", "risk": "User can redirect payment processing.", "impact": "SOD violation — Finance & Accounts (MyCom)", "mitigation": "Segregate 'Bank Master' and 'Batch Payments' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "ACC-013", "name": "Journal Voucher & Processing", "priority": "Critical", "cycle": "Finance & Accounts", "area": "Finance & Accounts", "system": "MyCom", "win1": "Journal Voucher", "win2": "Processing", "risk": "User can create and post own accounting entries.", "impact": "SOD violation — Finance & Accounts (MyCom)", "mitigation": "Segregate 'Journal Voucher' and 'Processing' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "ACC-014", "name": "Payable Invoice & Processing", "priority": "Critical", "cycle": "Finance & Accounts", "area": "Finance & Accounts", "system": "MyCom", "win1": "Payable Invoice", "win2": "Processing", "risk": "User can enter and post AP transactions.", "impact": "SOD violation — Finance & Accounts (MyCom)", "mitigation": "Segregate 'Payable Invoice' and 'Processing' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "ACC-015", "name": "Receivable Invoices & Processing", "priority": "Critical", "cycle": "Finance & Accounts", "area": "Finance & Accounts", "system": "MyCom", "win1": "Receivable Invoices", "win2": "Processing", "risk": "User can enter and post AR transactions.", "impact": "SOD violation — Finance & Accounts (MyCom)", "mitigation": "Segregate 'Receivable Invoices' and 'Processing' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "ACC-016", "name": "Journal Voucher & Month Closing", "priority": "Critical", "cycle": "Finance & Accounts", "area": "Finance & Accounts", "system": "MyCom", "win1": "Journal Voucher", "win2": "Month Closing", "risk": "User can pass adjustments and close period.", "impact": "SOD violation — Finance & Accounts (MyCom)", "mitigation": "Segregate 'Journal Voucher' and 'Month Closing' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "ACC-017", "name": "Journal Voucher & Account Closing", "priority": "Critical", "cycle": "Finance & Accounts", "area": "Finance & Accounts", "system": "MyCom", "win1": "Journal Voucher", "win2": "Account Closing", "risk": "User can manipulate year-end results.", "impact": "SOD violation — Finance & Accounts (MyCom)", "mitigation": "Segregate 'Journal Voucher' and 'Account Closing' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "ACC-018", "name": "Opening Balance & Journal Voucher", "priority": "High", "cycle": "Finance & Accounts", "area": "Finance & Accounts", "system": "MyCom", "win1": "Opening Balance", "win2": "Journal Voucher", "risk": "User can manipulate opening and operational balances.", "impact": "SOD violation — Finance & Accounts (MyCom)", "mitigation": "Segregate 'Opening Balance' and 'Journal Voucher' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "ACC-019", "name": "Opening Balance & Account Closing", "priority": "High", "cycle": "Finance & Accounts", "area": "Finance & Accounts", "system": "MyCom", "win1": "Opening Balance", "win2": "Account Closing", "risk": "User can influence financial results.", "impact": "SOD violation — Finance & Accounts (MyCom)", "mitigation": "Segregate 'Opening Balance' and 'Account Closing' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "ACC-020", "name": "User Setup & Payments", "priority": "Critical", "cycle": "Finance & Accounts", "area": "Finance & Accounts", "system": "MyCom", "win1": "User Setup", "win2": "Payments", "risk": "User can grant access and execute payments.", "impact": "SOD violation — Finance & Accounts (MyCom)", "mitigation": "Segregate 'User Setup' and 'Payments' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "ACC-021", "name": "User Setup & Supplier Master", "priority": "High", "cycle": "Finance & Accounts", "area": "Finance & Accounts", "system": "MyCom", "win1": "User Setup", "win2": "Supplier Master", "risk": "User controls supplier creation and security.", "impact": "SOD violation — Finance & Accounts (MyCom)", "mitigation": "Segregate 'User Setup' and 'Supplier Master' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "ACC-022", "name": "User Setup & Journal Voucher", "priority": "High", "cycle": "Finance & Accounts", "area": "Finance & Accounts", "system": "MyCom", "win1": "User Setup", "win2": "Journal Voucher", "risk": "User controls security and accounting entries.", "impact": "SOD violation — Finance & Accounts (MyCom)", "mitigation": "Segregate 'User Setup' and 'Journal Voucher' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "ACC-023", "name": "User Setup & Account Closing", "priority": "High", "cycle": "Finance & Accounts", "area": "Finance & Accounts", "system": "MyCom", "win1": "User Setup", "win2": "Account Closing", "risk": "User controls access and financial close.", "impact": "SOD violation — Finance & Accounts (MyCom)", "mitigation": "Segregate 'User Setup' and 'Account Closing' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "ACC-024", "name": "Bank Master & Inter Company Payments", "priority": "Critical", "cycle": "Finance & Accounts", "area": "Finance & Accounts", "system": "MyCom", "win1": "Bank Master", "win2": "Inter Company Payments", "risk": "User can redirect intercompany transfers.", "impact": "SOD violation — Finance & Accounts (MyCom)", "mitigation": "Segregate 'Bank Master' and 'Inter Company Payments' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "ACC-025", "name": "Inter Company Payments & Bank Reconciliation - Entry", "priority": "Critical", "cycle": "Finance & Accounts", "area": "Finance & Accounts", "system": "MyCom", "win1": "Inter Company Payments", "win2": "Bank Reconciliation - Entry", "risk": "User can transfer and reconcile transactions.", "impact": "SOD violation — Finance & Accounts (MyCom)", "mitigation": "Segregate 'Inter Company Payments' and 'Bank Reconciliation - Entry' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "ACC-026", "name": "Inter Company Receipts & Bank Reconciliation - Entry", "priority": "Critical", "cycle": "Finance & Accounts", "area": "Finance & Accounts", "system": "MyCom", "win1": "Inter Company Receipts", "win2": "Bank Reconciliation - Entry", "risk": "User can receive and reconcile transactions.", "impact": "SOD violation — Finance & Accounts (MyCom)", "mitigation": "Segregate 'Inter Company Receipts' and 'Bank Reconciliation - Entry' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "ACC-027", "name": "PDC Processing & Payments", "priority": "High", "cycle": "Finance & Accounts", "area": "Finance & Accounts", "system": "MyCom", "win1": "PDC Processing", "win2": "Payments", "risk": "User controls cheque issue and realization.", "impact": "SOD violation — Finance & Accounts (MyCom)", "mitigation": "Segregate 'PDC Processing' and 'Payments' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "ACC-028", "name": "PDC Processing & Receipts", "priority": "High", "cycle": "Finance & Accounts", "area": "Finance & Accounts", "system": "MyCom", "win1": "PDC Processing", "win2": "Receipts", "risk": "User controls receipt and cheque realization.", "impact": "SOD violation — Finance & Accounts (MyCom)", "mitigation": "Segregate 'PDC Processing' and 'Receipts' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "ACC-029", "name": "Document Serial & Payments", "priority": "High", "cycle": "Finance & Accounts", "area": "Finance & Accounts", "system": "MyCom", "win1": "Document Serial", "win2": "Payments", "risk": "User can manipulate voucher numbering and payments.", "impact": "SOD violation — Finance & Accounts (MyCom)", "mitigation": "Segregate 'Document Serial' and 'Payments' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "ACC-030", "name": "Document Control & Payments", "priority": "High", "cycle": "Finance & Accounts", "area": "Finance & Accounts", "system": "MyCom", "win1": "Document Control", "win2": "Payments", "risk": "User controls payment documents and transaction execution.", "impact": "SOD violation — Finance & Accounts (MyCom)", "mitigation": "Segregate 'Document Control' and 'Payments' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-001", "name": "Supplier Master (Vendor Information) & PO (Local Purchase Order)", "priority": "Critical", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "Supplier Master (Vendor Information)", "win2": "PO (Local Purchase Order)", "risk": "User can create suppliers and issue purchase orders to the same supplier.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'Supplier Master (Vendor Information)' and 'PO (Local Purchase Order)' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-002", "name": "Supplier Master (Vendor Information) & Supplier Contract", "priority": "Critical", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "Supplier Master (Vendor Information)", "win2": "Supplier Contract", "risk": "User can onboard suppliers and create/award supplier contracts.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'Supplier Master (Vendor Information)' and 'Supplier Contract' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-003", "name": "Supplier Master (Vendor Information) & RFQ", "priority": "Critical", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "Supplier Master (Vendor Information)", "win2": "RFQ", "risk": "User can create suppliers and initiate RFQs to preferred vendors.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'Supplier Master (Vendor Information)' and 'RFQ' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-004", "name": "Supplier Master (Vendor Information) & Quotation Hd", "priority": "Critical", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "Supplier Master (Vendor Information)", "win2": "Quotation Hd", "risk": "User can create suppliers and record supplier quotations.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'Supplier Master (Vendor Information)' and 'Quotation Hd' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-005", "name": "Supplier Master (Vendor Information) & GRN Entry", "priority": "Critical", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "Supplier Master (Vendor Information)", "win2": "GRN Entry", "risk": "User can create supplier and receive goods against that supplier.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'Supplier Master (Vendor Information)' and 'GRN Entry' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-006", "name": "Material Request & PO", "priority": "Critical", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "Material Request", "win2": "PO", "risk": "User can generate requirement and independently create purchase order.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'Material Request' and 'PO' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-007", "name": "Material Request & Supplier Contract", "priority": "Critical", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "Material Request", "win2": "Supplier Contract", "risk": "User can create demand and award contract without independent review.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'Material Request' and 'Supplier Contract' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-008", "name": "Material Request & RFQ", "priority": "High", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "Material Request", "win2": "RFQ", "risk": "User can raise demand and directly control sourcing process.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'Material Request' and 'RFQ' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-009", "name": "RFQ & Quotation Hd", "priority": "Critical", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "RFQ", "win2": "Quotation Hd", "risk": "User can request and record supplier quotations, potentially influencing supplier selection.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'RFQ' and 'Quotation Hd' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-010", "name": "RFQ & Quotation Comparison Report", "priority": "Critical", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "RFQ", "win2": "Quotation Comparison Report", "risk": "User can issue RFQ and evaluate supplier responses without segregation.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'RFQ' and 'Quotation Comparison Report' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-011", "name": "Quotation Hd & Supplier Contract", "priority": "Critical", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "Quotation Hd", "win2": "Supplier Contract", "risk": "User can create quotations and award contracts.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'Quotation Hd' and 'Supplier Contract' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-012", "name": "Quotation Hd & PO", "priority": "Critical", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "Quotation Hd", "win2": "PO", "risk": "User can create quotation and generate purchase order to same supplier.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'Quotation Hd' and 'PO' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-013", "name": "Quotation Comparison Report & PO", "priority": "Critical", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "Quotation Comparison Report", "win2": "PO", "risk": "User can evaluate quotations and award purchase order.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'Quotation Comparison Report' and 'PO' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-014", "name": "Quotation Comparison Report & Supplier Contract", "priority": "Critical", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "Quotation Comparison Report", "win2": "Supplier Contract", "risk": "User can evaluate bids and award contracts.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'Quotation Comparison Report' and 'Supplier Contract' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-015", "name": "Supplier Contract & PO", "priority": "Critical", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "Supplier Contract", "win2": "PO", "risk": "User can establish supplier agreement and place orders independently.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'Supplier Contract' and 'PO' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-016", "name": "Request Of Supply (ROS) & PO", "priority": "High", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "Request Of Supply (ROS)", "win2": "PO", "risk": "User can create supply request and convert it to PO without review.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'Request Of Supply (ROS)' and 'PO' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-017", "name": "PO & Permit Of Receiving", "priority": "Critical", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "PO", "win2": "Permit Of Receiving", "risk": "User can order and authorize receipt of goods.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'PO' and 'Permit Of Receiving' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-018", "name": "PO & GRN Entry", "priority": "Critical", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "PO", "win2": "GRN Entry", "risk": "User can issue PO and acknowledge receipt of goods.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'PO' and 'GRN Entry' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-019", "name": "PO & Transit Receiving", "priority": "Critical", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "PO", "win2": "Transit Receiving", "risk": "User can create PO and receive inventory on behalf of another location.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'PO' and 'Transit Receiving' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-020", "name": "Permit Of Receiving & GRN Entry", "priority": "High", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "Permit Of Receiving", "win2": "GRN Entry", "risk": "User can authorize and complete receipt process.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'Permit Of Receiving' and 'GRN Entry' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-021", "name": "Permit Of Receiving & Transit Receiving", "priority": "High", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "Permit Of Receiving", "win2": "Transit Receiving", "risk": "User can authorize and process transit receipts.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'Permit Of Receiving' and 'Transit Receiving' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-022", "name": "GRN Entry & Purchase Return", "priority": "Critical", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "GRN Entry", "win2": "Purchase Return", "risk": "User can receive goods and process supplier returns without review.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'GRN Entry' and 'Purchase Return' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-023", "name": "GRN Entry & Back Charge Justification", "priority": "High", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "GRN Entry", "win2": "Back Charge Justification", "risk": "User can receive goods and justify supplier penalties/claims.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'GRN Entry' and 'Back Charge Justification' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-024", "name": "Opening Balance & GRN Entry", "priority": "Critical", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "Opening Balance", "win2": "GRN Entry", "risk": "User can create inventory opening stock and record receipts.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'Opening Balance' and 'GRN Entry' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-025", "name": "Opening Balance & Issue", "priority": "Critical", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "Opening Balance", "win2": "Issue", "risk": "User can create stock and issue it without independent verification.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'Opening Balance' and 'Issue' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-026", "name": "Opening Balance & Transfer", "priority": "Critical", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "Opening Balance", "win2": "Transfer", "risk": "User can create inventory and transfer it between locations.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'Opening Balance' and 'Transfer' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-027", "name": "Transfer & Transfer Receive", "priority": "Critical", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "Transfer", "win2": "Transfer Receive", "risk": "User can dispatch and receive inventory transfers.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'Transfer' and 'Transfer Receive' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-028", "name": "Transfer & Issue", "priority": "High", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "Transfer", "win2": "Issue", "risk": "User can transfer and issue stock transactions.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'Transfer' and 'Issue' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-029", "name": "Delivery Process Entry & Issue", "priority": "Critical", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "Delivery Process Entry", "win2": "Issue", "risk": "User can prepare delivery and complete inventory issue.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'Delivery Process Entry' and 'Issue' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-030", "name": "Picking List & Issue", "priority": "High", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "Picking List", "win2": "Issue", "risk": "User can pick and issue goods without secondary check.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'Picking List' and 'Issue' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-031", "name": "Picking List & Delivery Process Entry", "priority": "High", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "Picking List", "win2": "Delivery Process Entry", "risk": "User controls inventory selection and dispatch process.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'Picking List' and 'Delivery Process Entry' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-032", "name": "Transfer Receive & GRN Entry", "priority": "High", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "Transfer Receive", "win2": "GRN Entry", "risk": "User can acknowledge transfer receipts and inventory receipts.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'Transfer Receive' and 'GRN Entry' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-033", "name": "Brand Master & Supplier Master", "priority": "Medium", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "Brand Master", "win2": "Supplier Master", "risk": "User can define brands and assign supplier relationships.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'Brand Master' and 'Supplier Master' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-034", "name": "Brand Master & PO", "priority": "High", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "Brand Master", "win2": "PO", "risk": "User can create brand definitions and procure related products.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'Brand Master' and 'PO' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-035", "name": "Item Contract Header & Item Contract Detail", "priority": "Low", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "Item Contract Header", "win2": "Item Contract Detail", "risk": "Normally acceptable combination but should be monitored for completeness.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'Item Contract Header' and 'Item Contract Detail' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-036", "name": "Item Contract Detail & PO", "priority": "High", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "Item Contract Detail", "win2": "PO", "risk": "User can maintain pricing contracts and create purchase orders.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'Item Contract Detail' and 'PO' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-037", "name": "Awarded Items Price Report & PO", "priority": "High", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "Awarded Items Price Report", "win2": "PO", "risk": "User can review awarded pricing and execute purchases.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'Awarded Items Price Report' and 'PO' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-038", "name": "LPO Confirm & PO", "priority": "Critical", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "LPO Confirm", "win2": "PO", "risk": "User can create and approve/confirm own purchase orders.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'LPO Confirm' and 'PO' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-039", "name": "LPO Confirm & GRN Entry", "priority": "Critical", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "LPO Confirm", "win2": "GRN Entry", "risk": "User can approve orders and record goods receipt.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'LPO Confirm' and 'GRN Entry' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-040", "name": "Request Of Supply & Supplier Contract", "priority": "High", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "Request Of Supply", "win2": "Supplier Contract", "risk": "User can request supply and establish supplier contract.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'Request Of Supply' and 'Supplier Contract' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-041", "name": "RFQ & Supplier Contract", "priority": "Critical", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "RFQ", "win2": "Supplier Contract", "risk": "User can perform sourcing and contract award activities.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'RFQ' and 'Supplier Contract' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-042", "name": "RFQ & PO", "priority": "Critical", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "RFQ", "win2": "PO", "risk": "User can conduct tendering and directly place purchase order.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'RFQ' and 'PO' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-043", "name": "Quotation Tran & Quotation Comparison Report", "priority": "High", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "Quotation Tran", "win2": "Quotation Comparison Report", "risk": "User can enter quotations and perform quote evaluation.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'Quotation Tran' and 'Quotation Comparison Report' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-044", "name": "Monthly Purchase Details & PO", "priority": "Medium", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "Monthly Purchase Details", "win2": "PO", "risk": "User can both execute and report procurement activity.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'Monthly Purchase Details' and 'PO' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-045", "name": "Fixed Price Report & Item Contract Detail", "priority": "Medium", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "Fixed Price Report", "win2": "Item Contract Detail", "risk": "User can maintain and validate contract pricing records.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'Fixed Price Report' and 'Item Contract Detail' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-046", "name": "Purchase Return & GRN Entry", "priority": "Critical", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "Purchase Return", "win2": "GRN Entry", "risk": "User can receive and reverse goods receipts.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'Purchase Return' and 'GRN Entry' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-047", "name": "Material Request & Issue", "priority": "Critical", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "Material Request", "win2": "Issue", "risk": "User can request and consume inventory.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'Material Request' and 'Issue' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-048", "name": "Material Request & GRN Entry", "priority": "Critical", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "Material Request", "win2": "GRN Entry", "risk": "User can request and receive inventory.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'Material Request' and 'GRN Entry' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-049", "name": "Material Request & Transfer Receive", "priority": "High", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "Material Request", "win2": "Transfer Receive", "risk": "User can request and acknowledge stock transfers.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'Material Request' and 'Transfer Receive' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PROC-050", "name": "Supplier Master & Purchase Return", "priority": "Critical", "cycle": "Procurement & Inventory", "area": "Procurement & Inventory", "system": "MyCom", "win1": "Supplier Master", "win2": "Purchase Return", "risk": "User can create supplier and process returns/claims against supplier.", "impact": "SOD violation — Procurement & Inventory (MyCom)", "mitigation": "Segregate 'Supplier Master' and 'Purchase Return' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PAY-001", "name": "EMPLOYEEMASTER & PAYROLL ATTENDENCE", "priority": "Critical", "cycle": "Payroll & HR", "area": "Payroll & HR", "system": "MyCom", "win1": "EMPLOYEEMASTER", "win2": "PAYROLL ATTENDENCE", "risk": "User can create or modify employee records and process attendance for the same employee, leading to fictitious employees or attendance manipulation.", "impact": "SOD violation — Payroll & HR (MyCom)", "mitigation": "Segregate 'EMPLOYEEMASTER' and 'PAYROLL ATTENDENCE' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PAY-002", "name": "EMPLOYEEMASTER & PAYROLL NONSTDPAYMENT", "priority": "Critical", "cycle": "Payroll & HR", "area": "Payroll & HR", "system": "MyCom", "win1": "EMPLOYEEMASTER", "win2": "PAYROLL NONSTDPAYMENT", "risk": "User can create employees and process unauthorized one-time payroll payments.", "impact": "SOD violation — Payroll & HR (MyCom)", "mitigation": "Segregate 'EMPLOYEEMASTER' and 'PAYROLL NONSTDPAYMENT' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PAY-003", "name": "EMPLOYEEMASTER & SALARY INCREMENT", "priority": "Critical", "cycle": "Payroll & HR", "area": "Payroll & HR", "system": "MyCom", "win1": "EMPLOYEEMASTER", "win2": "SALARY INCREMENT", "risk": "User can create employees and independently modify salary and compensation details.", "impact": "SOD violation — Payroll & HR (MyCom)", "mitigation": "Segregate 'EMPLOYEEMASTER' and 'SALARY INCREMENT' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PAY-004", "name": "EMPLOYEEMASTER & EMPLOYEE LOAN", "priority": "Critical", "cycle": "Payroll & HR", "area": "Payroll & HR", "system": "MyCom", "win1": "EMPLOYEEMASTER", "win2": "EMPLOYEE LOAN", "risk": "User can create employees and initiate unauthorized employee loans.", "impact": "SOD violation — Payroll & HR (MyCom)", "mitigation": "Segregate 'EMPLOYEEMASTER' and 'EMPLOYEE LOAN' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PAY-005", "name": "EMPLOYEEMASTER & EMPLOYEE TERMINATION", "priority": "Critical", "cycle": "Payroll & HR", "area": "Payroll & HR", "system": "MyCom", "win1": "EMPLOYEEMASTER", "win2": "EMPLOYEE TERMINATION", "risk": "User can create, modify, and terminate employee records without independent oversight.", "impact": "SOD violation — Payroll & HR (MyCom)", "mitigation": "Segregate 'EMPLOYEEMASTER' and 'EMPLOYEE TERMINATION' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PAY-006", "name": "EMPLOYEE LEAVE & ENCHASHMENT", "priority": "Critical", "cycle": "Payroll & HR", "area": "Payroll & HR", "system": "MyCom", "win1": "EMPLOYEE LEAVE", "win2": "ENCHASHMENT", "risk": "User can create leave records and subsequently process leave/ticket encashment for financial gain.", "impact": "SOD violation — Payroll & HR (MyCom)", "mitigation": "Segregate 'EMPLOYEE LEAVE' and 'ENCHASHMENT' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PAY-007", "name": "EMPLOYEE LEAVE & PAYROLL ATTENDENCE", "priority": "High", "cycle": "Payroll & HR", "area": "Payroll & HR", "system": "MyCom", "win1": "EMPLOYEE LEAVE", "win2": "PAYROLL ATTENDENCE", "risk": "User can manipulate leave records and attendance calculations impacting payroll.", "impact": "SOD violation — Payroll & HR (MyCom)", "mitigation": "Segregate 'EMPLOYEE LEAVE' and 'PAYROLL ATTENDENCE' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PAY-008", "name": "EMPLOYEE LEAVE & ALLOWANCE ADVANCE", "priority": "High", "cycle": "Payroll & HR", "area": "Payroll & HR", "system": "MyCom", "win1": "EMPLOYEE LEAVE", "win2": "ALLOWANCE ADVANCE", "risk": "User can initiate leave transactions and related advance payments.", "impact": "SOD violation — Payroll & HR (MyCom)", "mitigation": "Segregate 'EMPLOYEE LEAVE' and 'ALLOWANCE ADVANCE' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PAY-009", "name": "PAYROLL ATTENDENCE & PAYROLL NONSTDPAYMENT", "priority": "Critical", "cycle": "Payroll & HR", "area": "Payroll & HR", "system": "MyCom", "win1": "PAYROLL ATTENDENCE", "win2": "PAYROLL NONSTDPAYMENT", "risk": "User can influence payroll calculations through attendance and additional payments.", "impact": "SOD violation — Payroll & HR (MyCom)", "mitigation": "Segregate 'PAYROLL ATTENDENCE' and 'PAYROLL NONSTDPAYMENT' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PAY-010", "name": "PAYROLL ATTENDENCE & SALARY INCREMENT", "priority": "Critical", "cycle": "Payroll & HR", "area": "Payroll & HR", "system": "MyCom", "win1": "PAYROLL ATTENDENCE", "win2": "SALARY INCREMENT", "risk": "User can alter attendance inputs and compensation calculations affecting payroll results.", "impact": "SOD violation — Payroll & HR (MyCom)", "mitigation": "Segregate 'PAYROLL ATTENDENCE' and 'SALARY INCREMENT' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PAY-011", "name": "SALARY INCREMENT & PAYROLL NONSTDPAYMENT", "priority": "Critical", "cycle": "Payroll & HR", "area": "Payroll & HR", "system": "MyCom", "win1": "SALARY INCREMENT", "win2": "PAYROLL NONSTDPAYMENT", "risk": "User can increase employee compensation through salary revisions and one-time payments.", "impact": "SOD violation — Payroll & HR (MyCom)", "mitigation": "Segregate 'SALARY INCREMENT' and 'PAYROLL NONSTDPAYMENT' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PAY-012", "name": "SALARY INCREMENT & EMPLOYEE LOAN", "priority": "Critical", "cycle": "Payroll & HR", "area": "Payroll & HR", "system": "MyCom", "win1": "SALARY INCREMENT", "win2": "EMPLOYEE LOAN", "risk": "User can manipulate employee benefits through both salary revision and loan processing.", "impact": "SOD violation — Payroll & HR (MyCom)", "mitigation": "Segregate 'SALARY INCREMENT' and 'EMPLOYEE LOAN' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PAY-013", "name": "SALARY INCREMENT & PERFORMACE", "priority": "High", "cycle": "Payroll & HR", "area": "Payroll & HR", "system": "MyCom", "win1": "SALARY INCREMENT", "win2": "PERFORMACE", "risk": "User can perform assessments and approve salary revisions without independent review.", "impact": "SOD violation — Payroll & HR (MyCom)", "mitigation": "Segregate 'SALARY INCREMENT' and 'PERFORMACE' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PAY-014", "name": "EMPLOYEE LOAN & PAYROLL NONSTDPAYMENT", "priority": "Critical", "cycle": "Payroll & HR", "area": "Payroll & HR", "system": "MyCom", "win1": "EMPLOYEE LOAN", "win2": "PAYROLL NONSTDPAYMENT", "risk": "User can provide financial benefits through loans and additional payroll payments.", "impact": "SOD violation — Payroll & HR (MyCom)", "mitigation": "Segregate 'EMPLOYEE LOAN' and 'PAYROLL NONSTDPAYMENT' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PAY-015", "name": "EMPLOYEE LOAN & ALLOWANCE ADVANCE", "priority": "High", "cycle": "Payroll & HR", "area": "Payroll & HR", "system": "MyCom", "win1": "EMPLOYEE LOAN", "win2": "ALLOWANCE ADVANCE", "risk": "User can issue multiple forms of employee advances and recoverable benefits.", "impact": "SOD violation — Payroll & HR (MyCom)", "mitigation": "Segregate 'EMPLOYEE LOAN' and 'ALLOWANCE ADVANCE' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PAY-016", "name": "EMPLOYEE TERMINATION & ENCHASHMENT", "priority": "Critical", "cycle": "Payroll & HR", "area": "Payroll & HR", "system": "MyCom", "win1": "EMPLOYEE TERMINATION", "win2": "ENCHASHMENT", "risk": "User can terminate employees and process final encashment settlements.", "impact": "SOD violation — Payroll & HR (MyCom)", "mitigation": "Segregate 'EMPLOYEE TERMINATION' and 'ENCHASHMENT' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PAY-017", "name": "EMPLOYEE TERMINATION & EMPLOYEE LOAN", "priority": "High", "cycle": "Payroll & HR", "area": "Payroll & HR", "system": "MyCom", "win1": "EMPLOYEE TERMINATION", "win2": "EMPLOYEE LOAN", "risk": "User can influence final settlements and loan recovery calculations.", "impact": "SOD violation — Payroll & HR (MyCom)", "mitigation": "Segregate 'EMPLOYEE TERMINATION' and 'EMPLOYEE LOAN' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PAY-018", "name": "EMPLOYEE ACTION FORM & SALARY INCREMENT", "priority": "High", "cycle": "Payroll & HR", "area": "Payroll & HR", "system": "MyCom", "win1": "EMPLOYEE ACTION FORM", "win2": "SALARY INCREMENT", "risk": "User can record employee actions and directly influence compensation decisions.", "impact": "SOD violation — Payroll & HR (MyCom)", "mitigation": "Segregate 'EMPLOYEE ACTION FORM' and 'SALARY INCREMENT' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PAY-019", "name": "EMPLOYEE ACTION FORM & EMPLOYEE TERMINATION", "priority": "High", "cycle": "Payroll & HR", "area": "Payroll & HR", "system": "MyCom", "win1": "EMPLOYEE ACTION FORM", "win2": "EMPLOYEE TERMINATION", "risk": "User can initiate disciplinary actions and process employee separation.", "impact": "SOD violation — Payroll & HR (MyCom)", "mitigation": "Segregate 'EMPLOYEE ACTION FORM' and 'EMPLOYEE TERMINATION' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PAY-020", "name": "EMPLOYEE TRANSFER & SALARY INCREMENT", "priority": "High", "cycle": "Payroll & HR", "area": "Payroll & HR", "system": "MyCom", "win1": "EMPLOYEE TRANSFER", "win2": "SALARY INCREMENT", "risk": "User can modify organizational assignments and compensation concurrently.", "impact": "SOD violation — Payroll & HR (MyCom)", "mitigation": "Segregate 'EMPLOYEE TRANSFER' and 'SALARY INCREMENT' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PAY-021", "name": "EMPLOYEE TRANSFER & GROUP TRANSFER", "priority": "High", "cycle": "Payroll & HR", "area": "Payroll & HR", "system": "MyCom", "win1": "EMPLOYEE TRANSFER", "win2": "GROUP TRANSFER", "risk": "User can change employee organizational structure and group classification without review.", "impact": "SOD violation — Payroll & HR (MyCom)", "mitigation": "Segregate 'EMPLOYEE TRANSFER' and 'GROUP TRANSFER' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PAY-022", "name": "GROUP TRANSFER & TICKET FREQUENT", "priority": "High", "cycle": "Payroll & HR", "area": "Payroll & HR", "system": "MyCom", "win1": "GROUP TRANSFER", "win2": "TICKET FREQUENT", "risk": "User can modify employee groups and associated ticket entitlement frequencies.", "impact": "SOD violation — Payroll & HR (MyCom)", "mitigation": "Segregate 'GROUP TRANSFER' and 'TICKET FREQUENT' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PAY-023", "name": "PERFORMACE & SALARY INCREMENT", "priority": "High", "cycle": "Payroll & HR", "area": "Payroll & HR", "system": "MyCom", "win1": "PERFORMACE", "win2": "SALARY INCREMENT", "risk": "User can evaluate employee performance and grant salary increases based on self-controlled assessments.", "impact": "SOD violation — Payroll & HR (MyCom)", "mitigation": "Segregate 'PERFORMACE' and 'SALARY INCREMENT' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PAY-024", "name": "EMPLOYEE TERMINATION & PAYROLL NONSTDPAYMENT", "priority": "Critical", "cycle": "Payroll & HR", "area": "Payroll & HR", "system": "MyCom", "win1": "EMPLOYEE TERMINATION", "win2": "PAYROLL NONSTDPAYMENT", "risk": "User can terminate employees while processing additional payroll payments or settlements.", "impact": "SOD violation — Payroll & HR (MyCom)", "mitigation": "Segregate 'EMPLOYEE TERMINATION' and 'PAYROLL NONSTDPAYMENT' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PAY-025", "name": "EMPLOYEE TERMINATION & ALLOWANCE ADVANCE", "priority": "High", "cycle": "Payroll & HR", "area": "Payroll & HR", "system": "MyCom", "win1": "EMPLOYEE TERMINATION", "win2": "ALLOWANCE ADVANCE", "risk": "User can approve advances and process employee exit transactions.", "impact": "SOD violation — Payroll & HR (MyCom)", "mitigation": "Segregate 'EMPLOYEE TERMINATION' and 'ALLOWANCE ADVANCE' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PAY-026", "name": "EMPLOYEEMASTER & ENCHASHMENT", "priority": "Critical", "cycle": "Payroll & HR", "area": "Payroll & HR", "system": "MyCom", "win1": "EMPLOYEEMASTER", "win2": "ENCHASHMENT", "risk": "User can manipulate employee records and process leave/ticket encashments.", "impact": "SOD violation — Payroll & HR (MyCom)", "mitigation": "Segregate 'EMPLOYEEMASTER' and 'ENCHASHMENT' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PAY-027", "name": "EMPLOYEEMASTER & ALLOWANCE ADVANCE", "priority": "Critical", "cycle": "Payroll & HR", "area": "Payroll & HR", "system": "MyCom", "win1": "EMPLOYEEMASTER", "win2": "ALLOWANCE ADVANCE", "risk": "User can create or alter employee records and approve allowance advances.", "impact": "SOD violation — Payroll & HR (MyCom)", "mitigation": "Segregate 'EMPLOYEEMASTER' and 'ALLOWANCE ADVANCE' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PAY-028", "name": "EMPLOYEE TRANSFER & PAYROLL ATTENDENCE", "priority": "High", "cycle": "Payroll & HR", "area": "Payroll & HR", "system": "MyCom", "win1": "EMPLOYEE TRANSFER", "win2": "PAYROLL ATTENDENCE", "risk": "User can transfer employees and influence attendance allocation for payroll purposes.", "impact": "SOD violation — Payroll & HR (MyCom)", "mitigation": "Segregate 'EMPLOYEE TRANSFER' and 'PAYROLL ATTENDENCE' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PAY-029", "name": "GROUP TRANSFER & PAYROLL ATTENDENCE", "priority": "High", "cycle": "Payroll & HR", "area": "Payroll & HR", "system": "MyCom", "win1": "GROUP TRANSFER", "win2": "PAYROLL ATTENDENCE", "risk": "User can alter employee group classification that impacts attendance and payroll calculations.", "impact": "SOD violation — Payroll & HR (MyCom)", "mitigation": "Segregate 'GROUP TRANSFER' and 'PAYROLL ATTENDENCE' access between different users; enforce independent review/approval and periodic access recertification."},
  {"ruleId": "PAY-030", "name": "TICKET OPENING & ENCHASHMENT", "priority": "High", "cycle": "Payroll & HR", "area": "Payroll & HR", "system": "MyCom", "win1": "TICKET OPENING", "win2": "ENCHASHMENT", "risk": "User can establish ticket entitlements and subsequently process ticket encashment transactions.", "impact": "SOD violation — Payroll & HR (MyCom)", "mitigation": "Segregate 'TICKET OPENING' and 'ENCHASHMENT' access between different users; enforce independent review/approval and periodic access recertification."}
];

function normW(s){return String(s==null?'':s).toLowerCase().replace(/[^a-z0-9]+/g,' ').trim()}
const SPELL_FIX=[
  [/enchashment/g,'encashment'],[/attendence/g,'attendance'],[/performace/g,'performance'],
  [/nonstdpayment/g,'nonstandardpayment'],[/non std payment/g,'nonstandardpayment']
];
function canonW(s){ let x=normW(s); for(const [a,b] of SPELL_FIX) x=x.replace(a,b); return x.replace(/ /g,''); }
function windowAliases(w){
  const out=new Set([canonW(w)]);
  const m=String(w).match(/^(.*?)\s*\((.*?)\)\s*$/);
  if(m){ if(m[1].trim()) out.add(canonW(m[1])); if(m[2].trim()) out.add(canonW(m[2])); }
  return out;
}
let _aliasGroups=null;
function buildAliasGroups(){
  const groups=[]; const byAlias={};
  for(const r of MYCOM_CONFLICTS){
    for(const w of [r.win1,r.win2]){
      const al=[...windowAliases(w)]; let gi=-1;
      for(const a of al){ if(byAlias[a]!==undefined){gi=byAlias[a];break} }
      if(gi<0){gi=groups.length;groups.push(new Set())}
      for(const a of al){
        const prev=byAlias[a];
        if(prev!==undefined&&prev!==gi){ for(const x of groups[prev]){groups[gi].add(x);byAlias[x]=gi} groups[prev]=new Set(); }
        groups[gi].add(a);byAlias[a]=gi;
      }
    }
  }
  _aliasGroups={groups,byAlias};
}
function expandedAliases(w){
  if(!_aliasGroups) buildAliasGroups();
  for(const a of windowAliases(w)){
    const gi=_aliasGroups.byAlias[a];
    if(gi!==undefined) return _aliasGroups.groups[gi];
  }
  return windowAliases(w);
}
const SPECIAL_FUNCS={
  'newf9':'add','new':'add','insertdetailf11':'add','insertdetail':'add','add':'add','insert':'add',
  'editf8':'edit','savef10':'edit','save':'edit','saveas':'edit','upload':'edit','process':'edit','cancelf4':'edit','cancel':'edit',
  'setup':'setup','delete':'del',
  'printctrlp':'print','printsetup':'print','previewctrlz':'print','preview':'print','exporttoexcel':'print',
  'file':null,'retrievectrlr':null,'retrieve':null,'zoomin':null,'zoomout':null,
  'closectrlw':null,'close':null,'searchf6':null,'search':null,
  'first':null,'previous':null,'next':null,'last':null,
  'record':null,'documentattachments':null,'print':'print','edit':'edit','view':null
};
function specialFunc(canonKey){
  if(Object.prototype.hasOwnProperty.call(SPECIAL_FUNCS,canonKey)) return SPECIAL_FUNCS[canonKey];
  const stripped=canonKey.replace(/(f\d+|ctrl[a-z]?)$/,'');
  if(stripped!==canonKey&&Object.prototype.hasOwnProperty.call(SPECIAL_FUNCS,stripped)) return SPECIAL_FUNCS[stripped];
  return undefined;
}
const SF_CAP_DESC={add:'To create / add new transactions',edit:'To edit the transactions',del:'To delete the transaction',print:'To print / output the transaction',setup:'To setup / change the particular transaction'};
const SF_NAME_DESC={
  'newf9':'To create new transactions','new':'To create new transactions','insertdetailf11':'To insert detail lines','insertdetail':'To insert detail lines',
  'editf8':'To edit the transactions','edit':'To edit the transactions','savef10':'To save','save':'To save','saveas':'To save a copy',
  'upload':'To upload transactions','process':'To process the transaction','cancelf4':'To cancel the transaction','cancel':'To cancel the transaction',
  'delete':'To delete the transaction','setup':'To setup / change the particular transaction',
  'printctrlp':'To print','print':'To print','printsetup':'To configure printing',
  'add':'To create / add new transactions','insert':'To insert new entries','view':'To view the transactions',
  'previewctrlz':'To preview','preview':'To preview','exporttoexcel':'To export to Excel'
};
function sfDetails(r,capMap){
  const via=cap=>{const s=capMap&&capMap[cap];return (s&&s.length)?` (via ${[...new Set(s)].sort().join(', ')})`:''};
  const out=[];
  if(r.setupViaSF) out.push('Setup — '+SF_CAP_DESC.setup+via('setup'));
  if(r.addViaSF) out.push('Add — '+SF_CAP_DESC.add+via('add'));
  if(r.editViaSF) out.push('Edit — '+SF_CAP_DESC.edit+via('edit'));
  if(r.delViaSF) out.push('Delete — '+SF_CAP_DESC.del+via('del'));
  if(r.printViaSF) out.push('Print — '+SF_CAP_DESC.print+via('print'));
  return out;
}
function sfNameDesc(n){
  const k=canonW(n);
  if(SF_NAME_DESC[k]) return SF_NAME_DESC[k];
  const s=k.replace(/(f\d+|ctrl[a-z]?)$/,'');
  return SF_NAME_DESC[s]||'';
}
function sfMenuList(names){
  if(!names||!names.length) return [];
  return [...new Set(names)].sort().map(n=>{const dsc=sfNameDesc(n);return dsc?`${n} — ${dsc}`:n});
}
function accessHTML(r){
  const chips=[];
  const push=(label,cls,title)=>chips.push(`<span class="cap-chip ${cls}"${title?` title="${String(title).replace(/"/g,'&quot;')}"`:''}>${label}</span>`);
  if(r.menu) push('Menu','cap-menu','Module access flag = Yes (implies View, Edit, Delete)');
  if(r.setup) push('Setup^','cap-sf',SF_CAP_DESC.setup);
  if(r.view){ if(r.viewDirect) push('View','cap-direct'); else push('View*','cap-menu','Implied by Menu = Yes'); }
  if(r.add){ if(r.addDirect) push('Add','cap-direct'); else if(r.addViaSF) push('Add^','cap-sf',SF_CAP_DESC.add); else push('Add*','cap-menu','Implied by Menu = Yes'); }
  if(r.edit){ if(r.editDirect) push('Edit','cap-direct'); else if(r.editViaSF) push('Edit^','cap-sf',SF_CAP_DESC.edit); else push('Edit*','cap-menu','Implied by Menu = Yes'); }
  if(r.del){ if(r.delDirect) push('Delete','cap-direct'); else if(r.delViaSF) push('Delete^','cap-sf',SF_CAP_DESC.del); else push('Delete*','cap-menu','Implied by Menu = Yes'); }
  if(r.print){ if(r.printDirect) push('Print','cap-direct'); else if(r.printViaSF) push('Print^','cap-sf',SF_CAP_DESC.print); else push('Print*','cap-menu','Implied by Menu = Yes'); }
  return chips.join('')||'<span class="cap-chip cap-none">—</span>';
}
function accessStr(r){
  const parts=[];
  if(r.menu) parts.push('Menu');
  const mark=(base,direct,viaSF,viaMenu)=>base+(direct?'':(viaSF?'^':(viaMenu?'*':'')));
  if(r.setup) parts.push('Setup'+(r.setupViaSF?'^':''));
  if(r.view) parts.push(mark('View',r.viewDirect,false,r.menu));
  if(r.add) parts.push(mark('Add',r.addDirect,r.addViaSF,r.addViaMenu));
  if(r.edit) parts.push(mark('Edit',r.editDirect,r.editViaSF,r.menu));
  if(r.del) parts.push(mark('Delete',r.delDirect,r.delViaSF,r.menu));
  if(r.print) parts.push(mark('Print',r.printDirect,r.printViaSF,r.printViaMenu));
  return parts.join(', ');
}

const NONE='__none__';
const YES=new Set(['y','yes','true','x','1','✓','yeah','ok']);
function isYes(v){return YES.has(String(v==null?'':v).trim().toLowerCase())}

// ═══════════════════════════════════════════════════════════════
// MYCOM ENGINE — accepts pre-extracted raw rows (already read from
// Excel client-side) + column mapping + options. All matching logic
// (special-function detection, alias grouping, rule evaluation) runs
// here so it never reaches the browser.
//
// Input shape:
//  {
//    layout: 'direct' | 'groups' | 'multi',
//    options: { impliesAll, applySF, trigger, scope },
//    // direct:
//    rows: [...], colMap: {user, window, group, menuFlag, view, add, edit, del, print}
//    // groups:
//    sheet1Rows, sheet2Rows, colMap: {..., g2Group}
//    // multi:
//    files: [{ loc, sheets: [{ rows, colMap }] }]
//  }
// ═══════════════════════════════════════════════════════════════
function runMyComServer(payload){
  const { layout, options } = payload;
  const impliesAll = !!options.impliesAll;
  const applySF = options.applySF !== false;
  const trigger = options.trigger || 'write';
  const scope = options.scope || 'perloc';

  if(!_aliasGroups) buildAliasGroups();
  const matrixAliasSet = new Set();
  for(const g of _aliasGroups.groups) for(const al of g) matrixAliasSet.add(al);

  const newRec = name => ({name,menu:false,view:false,add:false,edit:false,del:false,print:false,
    viewDirect:false,addDirect:false,editDirect:false,delDirect:false,printDirect:false,addViaMenu:false,printViaMenu:false,
    addViaSF:false,editViaSF:false,delViaSF:false,printViaSF:false,setup:false,setupViaSF:false,groups:new Set(),locs:new Set()});
  const grantsAnything = r => r.menu||r.view||r.add||r.edit||r.del||r.print||r.setup;

  function applyRow(rec,row,cm){
    const g=k=>k&&k!==NONE?row[k]:undefined;
    if(cm.menuFlag && cm.menuFlag!==NONE && isYes(g(cm.menuFlag))){
      rec.menu=true; rec.view=true; rec.edit=true; rec.del=true;
      if(impliesAll){ rec.add=true; rec.addViaMenu=true; rec.print=true; rec.printViaMenu=true; }
    }
    if(cm.view && cm.view!==NONE && isYes(g(cm.view))){rec.view=true;rec.viewDirect=true}
    if(cm.add && cm.add!==NONE && isYes(g(cm.add))){rec.add=true;rec.addDirect=true}
    if(cm.edit && cm.edit!==NONE && isYes(g(cm.edit))){rec.edit=true;rec.editDirect=true}
    if(cm.del && cm.del!==NONE && isYes(g(cm.del))){rec.del=true;rec.delDirect=true}
    if(cm.print && cm.print!==NONE && isYes(g(cm.print))){rec.print=true;rec.printDirect=true}
  }
  function rowGrants(row,cm){
    const g=k=>k&&k!==NONE?row[k]:undefined;
    return isYes(g(cm.menuFlag))||isYes(g(cm.view))||isYes(g(cm.add))||isYes(g(cm.edit))||isYes(g(cm.del))||isYes(g(cm.print));
  }
  function hasGranularFlags(row,cm){
    const g=k=>k&&k!==NONE?row[k]:undefined;
    return isYes(g(cm.add))||isYes(g(cm.edit))||isYes(g(cm.del))||isYes(g(cm.print));
  }
  function sfOf(key,row,cm){
    return (matrixAliasSet.has(key)||hasGranularFlags(row,cm)||!applySF) ? undefined : specialFunc(key);
  }

  const allUsers = new Set();

  // Build normalized per-location per-user window structures
  const perLoc = {};       // loc -> user -> {key: rec}
  const perLocSF = {};     // loc -> user -> {cap: [names]}
  const perLocSFNames = {};// loc -> user -> Set(names)
  const sfNamesAll = {};   // user -> Set(names) across all locations (banner)

  function ensureLoc(loc){
    if(!perLoc[loc]){perLoc[loc]={};perLocSF[loc]={};perLocSFNames[loc]={};}
  }
  function addSF(loc,u,cap,name){
    if(!perLocSF[loc][u]) perLocSF[loc][u]={};
    if(!perLocSFNames[loc][u]) perLocSFNames[loc][u]=new Set();
    if(cap){ if(!perLocSF[loc][u][cap]) perLocSF[loc][u][cap]=[]; perLocSF[loc][u][cap].push(name); }
    perLocSFNames[loc][u].add(name);
    if(!sfNamesAll[u]) sfNamesAll[u]=new Set();
    sfNamesAll[u].add(name);
  }

  function ingestRows(loc, rows, cm){
    ensureLoc(loc);
    for(const row of rows){
      const u = String(row[cm.user]||'').trim().toLowerCase();
      const wRaw = String(row[cm.window]||'').trim();
      if(!u||!wRaw) continue;
      allUsers.add(u);
      const key = canonW(wRaw);
      if(!key) continue;
      const sf = sfOf(key,row,cm);
      if(sf!==undefined){
        if(rowGrants(row,cm)) addSF(loc,u,sf,wRaw);
        continue;
      }
      if(!perLoc[loc][u]) perLoc[loc][u]={};
      if(!perLoc[loc][u][key]) perLoc[loc][u][key]=newRec(wRaw);
      const rec = perLoc[loc][u][key];
      rec.locs.add(loc);
      if(cm.group && cm.group!==NONE && rowGrants(row,cm)){
        const g=String(row[cm.group]||'').trim(); if(g) rec.groups.add(g);
      }
      applyRow(rec,row,cm);
    }
  }

  if(layout==='direct'){
    ingestRows('__single__', payload.rows||[], payload.colMap||{});
  } else if(layout==='groups'){
    const cm = payload.colMap||{};
    const userGroups = {};
    for(const row of (payload.sheet1Rows||[])){
      const u = String(row[cm.user]||'').trim().toLowerCase();
      const g = String(row[cm.group]||'').trim();
      if(!u) continue; allUsers.add(u);
      if(!g) continue;
      if(!userGroups[u]) userGroups[u]=new Set();
      userGroups[u].add(g);
    }
    const groupWins = {}; const groupSF = {};
    for(const row of (payload.sheet2Rows||[])){
      const g = String(row[cm.g2Group]||'').trim();
      const wRaw = String(row[cm.window]||'').trim();
      if(!g||!wRaw) continue;
      const key = canonW(wRaw);
      if(!key) continue;
      const sf = sfOf(key,row,cm);
      if(sf!==undefined){
        if(rowGrants(row,cm)){ if(!groupSF[g]) groupSF[g]=[]; groupSF[g].push({cap:sf,name:wRaw}); }
        continue;
      }
      if(!groupWins[g]) groupWins[g]={};
      if(!groupWins[g][key]) groupWins[g][key]=newRec(wRaw);
      applyRow(groupWins[g][key],row,cm);
    }
    ensureLoc('__single__');
    for(const [u,groups] of Object.entries(userGroups)){
      for(const g of groups){
        for(const s of (groupSF[g]||[])) addSF('__single__',u,s.cap,s.name);
        const gw = groupWins[g]; if(!gw) continue;
        for(const [key,src] of Object.entries(gw)){
          if(!grantsAnything(src)) continue;
          if(!perLoc['__single__'][u]) perLoc['__single__'][u]={};
          if(!perLoc['__single__'][u][key]) perLoc['__single__'][u][key]=newRec(src.name);
          const rec = perLoc['__single__'][u][key];
          for(const k of ['menu','view','add','edit','del','print','viewDirect','addDirect','editDirect','delDirect','printDirect','addViaMenu','printViaMenu'])
            rec[k]=rec[k]||src[k];
          rec.groups.add(g);
        }
      }
    }
  } else if(layout==='multi'){
    for(const f of (payload.files||[])){
      const loc = (f.loc||'').trim() || 'Location';
      for(const sh of (f.sheets||[])) ingestRows(loc, sh.rows||[], sh.colMap||{});
    }
  }

  // Overlay special functions (module Y/N gates everything)
  for(const [loc,users] of Object.entries(perLoc)){
    for(const wins of Object.values(users)) for(const rec of Object.values(wins)) rec.baseAccess = grantsAnything(rec);
    const CAP_FLAG={add:['add','addViaSF'],edit:['edit','editViaSF'],del:['del','delViaSF'],print:['print','printViaSF']};
    for(const [u,capMap] of Object.entries(perLocSF[loc]||{})){
      const wins = users[u]; if(!wins) continue;
      for(const cap of Object.keys(capMap)){
        if(cap==='setup'){
          for(const rec of Object.values(wins)){
            if(!rec.baseAccess) continue;
            rec.setup=true; rec.setupViaSF=true;
            for(const [fl,mk] of [['add','addViaSF'],['edit','editViaSF'],['del','delViaSF']])
              if(!rec[fl]){rec[fl]=true;rec[mk]=true}
          }
          continue;
        }
        const [fl,mk]=CAP_FLAG[cap];
        for(const rec of Object.values(wins)){
          if(!rec.baseAccess) continue;
          if(!rec[fl]){rec[fl]=true;rec[mk]=true}
        }
      }
    }
  }

  const qualifies = rec => trigger==='any'
    ? (rec.menu||rec.view||rec.add||rec.edit||rec.del||rec.print||rec.setup)
    : (rec.menu||rec.add||rec.edit||rec.del||rec.setup);
  const ruleAliases = MYCOM_CONFLICTS.map(r=>({r,a1:expandedAliases(r.win1),a2:expandedAliases(r.win2)}));
  const matchWin = (wins,al) => { const h=[]; for(const k of Object.keys(wins)){ if(al.has(k)&&qualifies(wins[k])) h.push(wins[k]); } return h.length?h:null; };

  const mkFinding = (r,u,h1,h2,loc,capMap,namesSet) => {
    const fn = [...(namesSet||[])].sort();
    return {
      type:'user',
      conflict:{name:r.name,ruleId:r.ruleId,priority:r.priority,cycle:r.cycle,area:r.area,system:'MyCom',task1:r.win1,task2:r.win2,risk:r.risk,impact:r.impact,mitigation:r.mitigation},
      user:u, location: loc==='__single__'?undefined:loc,
      sfMenus: sfMenuList([...(namesSet||[])]),
      winsA: h1.map(h=>({name:h.name,access:accessStr(h),accessHtml:accessHTML(h),sf:sfDetails(h,capMap),fn,groups:[...h.groups],locs:[...h.locs]})),
      winsB: h2.map(h=>({name:h.name,access:accessStr(h),accessHtml:accessHTML(h),sf:sfDetails(h,capMap),fn,groups:[...h.groups],locs:[...h.locs]}))
    };
  };

  const findings = [];
  let userWindowsForClean = {};

  if(layout!=='multi' || scope==='perloc'){
    for(const [loc,users] of Object.entries(perLoc)){
      for(const [u,wins] of Object.entries(users)){
        const capMap = (perLocSF[loc]||{})[u]||{};
        const namesSet = (perLocSFNames[loc]||{})[u];
        for(const {r,a1,a2} of ruleAliases){
          const h1=matchWin(wins,a1), h2=matchWin(wins,a2);
          if(h1&&h2) findings.push(mkFinding(r,u,h1,h2,loc,capMap,namesSet));
        }
      }
    }
    for(const users of Object.values(perLoc))
      for(const [u,wins] of Object.entries(users)){
        if(!userWindowsForClean[u]) userWindowsForClean[u]={};
        for(const [k,rec] of Object.entries(wins)) if(grantsAnything(rec)) userWindowsForClean[u][k]={name:rec.name};
      }
  } else {
    // consolidated (multi-file only)
    const merged = {};
    for(const [loc,users] of Object.entries(perLoc)){
      for(const [u,wins] of Object.entries(users)){
        if(!merged[u]) merged[u]={};
        for(const [k,src] of Object.entries(wins)){
          if(!grantsAnything(src)) continue;
          if(!merged[u][k]) merged[u][k]=newRec(src.name);
          const rec=merged[u][k];
          for(const fl of ['menu','view','add','edit','del','print','setup','viewDirect','addDirect','editDirect','delDirect','printDirect','addViaMenu','printViaMenu','addViaSF','editViaSF','delViaSF','printViaSF','setupViaSF'])
            rec[fl]=rec[fl]||src[fl];
          for(const g of src.groups) rec.groups.add(g);
          for(const l of src.locs) rec.locs.add(l);
        }
      }
    }
    const mergedSF = {};
    for(const loc of Object.keys(perLocSF))
      for(const [u,capMap] of Object.entries(perLocSF[loc]||{})){
        if(!mergedSF[u]) mergedSF[u]={};
        for(const [cap,names] of Object.entries(capMap)){
          if(!mergedSF[u][cap]) mergedSF[u][cap]=[];
          mergedSF[u][cap].push(...names);
        }
      }
    for(const [u,wins] of Object.entries(merged)){
      for(const {r,a1,a2} of ruleAliases){
        const h1=matchWin(wins,a1), h2=matchWin(wins,a2);
        if(h1&&h2) findings.push(mkFinding(r,u,h1,h2,'Consolidated',mergedSF[u]||{},sfNamesAll[u]));
      }
    }
    userWindowsForClean = merged;
  }

  // Unmatched windows diagnostic
  const unmatchedMap = {};
  for(const users of Object.values(perLoc))
    for(const wins of Object.values(users))
      for(const [key,rec] of Object.entries(wins))
        if(!matrixAliasSet.has(key)) unmatchedMap[key]=rec.name;

  const userSFNamesOut = {};
  for(const [u,set] of Object.entries(sfNamesAll)) userSFNamesOut[u]=[...set];

  return {
    results: findings,
    totalUsers: allUsers.size,
    userWindows: userWindowsForClean,
    userSFNames: userSFNamesOut,
    unmatchedWindows: Object.values(unmatchedMap).sort((a,b)=>a.localeCompare(b))
  };
}

// ═══════════════════════════════════════════════════════════════
// SINGLE-USER QUICK CHECK — spot-check one person's manually-entered
// window/flag rows without a full file upload. Mirrors runMyComServer's
// row-processing + special-function overlay + module gating exactly
// (same algorithm, same helper functions), just fed from a handful of
// manually-entered rows for one person instead of an uploaded sheet.
// ═══════════════════════════════════════════════════════════════
function getMyComVocab(){
  return {
    windows: [...new Set(MYCOM_CONFLICTS.flatMap(r=>[r.win1,r.win2]))].sort((a,b)=>a.localeCompare(b))
  };
}

function runMyComQuickCheck(rows, opts){
  opts = opts || {};
  const impliesAll=opts.impliesAll, applySF=opts.applySF!==false, trigger=opts.trigger||'write';
  const newRec = name=>({name,menu:false,view:false,add:false,edit:false,del:false,print:false,
    viewDirect:false,addDirect:false,editDirect:false,delDirect:false,printDirect:false,addViaMenu:false,printViaMenu:false,
    addViaSF:false,editViaSF:false,delViaSF:false,printViaSF:false,setup:false,setupViaSF:false,groups:new Set()});
  const grantsAnything = r=>r.menu||r.view||r.add||r.edit||r.del||r.print;

  if(!_aliasGroups) buildAliasGroups();
  const matrixAliasSet = new Set();
  for(const g of _aliasGroups.groups) for(const a of g) matrixAliasSet.add(a);

  const wins = {};
  const sfCapMap = {};
  const sfNamesSet = new Set();

  for(const row of (rows||[])){
    const wRaw = (row.window||'').trim();
    if(!wRaw) continue;
    const key = canonW(wRaw);
    if(!key) continue;
    const hasGranular = row.add||row.edit||row.del||row.print;
    const rowGrants = row.menu||row.view||row.add||row.edit||row.del||row.print;
    const sf = applySF ? ((matrixAliasSet.has(key)||hasGranular) ? undefined : specialFunc(key)) : undefined;
    if(sf!==undefined){
      if(rowGrants){
        if(sf){ if(!sfCapMap[sf]) sfCapMap[sf]=new Set(); sfCapMap[sf].add(wRaw); }
        sfNamesSet.add(wRaw);
      }
      continue;
    }
    if(!wins[key]) wins[key]=newRec(wRaw);
    const rec = wins[key];
    if(row.menu){
      rec.menu=true; rec.view=true; rec.edit=true; rec.del=true;
      if(impliesAll){ rec.add=true; rec.addViaMenu=true; rec.print=true; rec.printViaMenu=true; }
    }
    if(row.view){ rec.view=true; rec.viewDirect=true; }
    if(row.add){ rec.add=true; rec.addDirect=true; }
    if(row.edit){ rec.edit=true; rec.editDirect=true; }
    if(row.del){ rec.del=true; rec.delDirect=true; }
    if(row.print){ rec.print=true; rec.printDirect=true; }
  }

  for(const rec of Object.values(wins)) rec.baseAccess = grantsAnything(rec);
  const CAP_FLAG={add:['add','addViaSF'],edit:['edit','editViaSF'],del:['del','delViaSF'],print:['print','printViaSF']};
  for(const cap of Object.keys(sfCapMap)){
    if(cap==='setup'){
      for(const rec of Object.values(wins)){
        if(!rec.baseAccess) continue;
        rec.setup=true; rec.setupViaSF=true;
        for(const [fl,mk] of [['add','addViaSF'],['edit','editViaSF'],['del','delViaSF']])
          if(!rec[fl]){ rec[fl]=true; rec[mk]=true; }
      }
      continue;
    }
    const pair = CAP_FLAG[cap];
    if(!pair) continue;
    const [fl,mk]=pair;
    for(const rec of Object.values(wins)){
      if(!rec.baseAccess) continue;
      if(!rec[fl]){ rec[fl]=true; rec[mk]=true; }
    }
  }

  const qualifies = rec=>{
    if(!rec) return false;
    return trigger==='any'
      ? (rec.menu||rec.view||rec.add||rec.edit||rec.del||rec.print||rec.setup)
      : (rec.menu||rec.add||rec.edit||rec.del||rec.setup);
  };
  const matchWin = (winsMap, aliases)=>{
    const hits=[];
    for(const key of Object.keys(winsMap)) if(aliases.has(key)&&qualifies(winsMap[key])) hits.push(winsMap[key]);
    return hits.length?hits:null;
  };

  const sfMenus = sfMenuList([...sfNamesSet]);
  const findings=[];
  for(const r of MYCOM_CONFLICTS){
    const a1=expandedAliases(r.win1), a2=expandedAliases(r.win2);
    const h1=matchWin(wins,a1), h2=matchWin(wins,a2);
    if(h1&&h2){
      findings.push({
        conflict:{name:r.name,ruleId:r.ruleId,priority:r.priority,cycle:r.cycle,system:'MyCom',task1:r.win1,task2:r.win2,risk:r.risk,mitigation:r.mitigation},
        sfMenus,
        winsA:h1.map(h=>({name:h.name,access:accessStr(h),accessHtml:accessHTML(h),sf:sfDetails(h,sfCapMap)})),
        winsB:h2.map(h=>({name:h.name,access:accessStr(h),accessHtml:accessHTML(h),sf:sfDetails(h,sfCapMap)})),
      });
    }
  }
  return findings;
}

module.exports = { MYCOM_CONFLICTS, runMyComServer, canonW, sfNameDesc, getMyComVocab, runMyComQuickCheck };
