// FORENSYS Mock Data Generator
// Realistic cybersecurity alerts, incidents, and threat data

export interface Alert {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  source: string;
  timestamp: Date;
  status: 'new' | 'acknowledged' | 'investigating' | 'resolved';
  affectedAssets: string[];
  mitreTactics: string[];
}

export interface Incident {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'open' | 'investigating' | 'contained' | 'resolved';
  createdAt: Date;
  lastUpdated: Date;
  affectedSystems: string[];
  investigator: string;
  description: string;
  evidenceCount: number;
  relatedAlerts: string[];
}

export interface ThreatIntel {
  id: string;
  type: 'malware' | 'ioc' | 'vulnerability' | 'campaign';
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  indicators: string[];
  lastSeen: Date;
  confidence: number;
}

export interface Device {
  id: string;
  name: string;
  osType: string;
  lastSeen: Date;
  status: 'healthy' | 'compromised' | 'at-risk' | 'quarantined';
  riskScore: number;
  alertCount: number;
  owner: string;
}

export interface User {
  id: string;
  name: string;
  email: string;
  department: string;
  lastActive: Date;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  alertCount: number;
}

const alertTitles = [
  'Suspicious Network Activity Detected',
  'Potential Ransomware Encryption Detected',
  'Unauthorized Admin Access Attempt',
  'Malware Detected in Email Attachment',
  'Abnormal Process Execution',
  'Data Exfiltration Attempt',
  'Lateral Movement Detected',
  'Failed Authentication Attempts',
  'Registry Modification Detected',
  'Suspicious PowerShell Execution',
  'Command and Control Communication',
  'Privilege Escalation Attempt',
  'Credential Dumping Activity',
  'Persistence Mechanism Detected',
  'Zero-Day Exploit Attempt',
];

const alertSources = [
  'Endpoint Detection & Response',
  'Network Intrusion Detection',
  'Email Gateway',
  'Firewall',
  'Proxy Server',
  'Antivirus Engine',
  'Behavioral Analytics',
  'Vulnerability Scanner',
  'Web Application Firewall',
];

const mitreTactics = [
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
];

const affectedAssets = [
  'WEBSERVER-01',
  'DBSERVER-02',
  'WORKSTATION-43',
  'LAPTOP-USER-22',
  'FILESERVER-05',
  'DOMAIN-CONTROLLER',
  'VPNGATEWAY-01',
  'MAILSERVER-01',
  'APPSERVER-03',
  'SECURITYCAM-12',
];

const users = [
  { name: 'John Smith', email: 'john.smith@company.com', department: 'Finance' },
  { name: 'Sarah Johnson', email: 'sarah.j@company.com', department: 'Engineering' },
  { name: 'Michael Chen', email: 'm.chen@company.com', department: 'Operations' },
  { name: 'Emily Brown', email: 'emily.brown@company.com', department: 'HR' },
  { name: 'David Rodriguez', email: 'd.rodriguez@company.com', department: 'Sales' },
  { name: 'Lisa Anderson', email: 'l.anderson@company.com', department: 'Engineering' },
  { name: 'James Wilson', email: 'j.wilson@company.com', department: 'Finance' },
  { name: 'Jennifer Lee', email: 'jen.lee@company.com', department: 'Marketing' },
];

const companies = [
  'Acme Corp',
  'TechNova Solutions',
  'SecureNet Inc',
  'CloudGuard Systems',
  'DataShield Enterprise',
  'CyberDefense Co',
  'GlobalTech Security',
  'Enterprise Security Group',
];

function randomElement<T>(array: T[]): T {
  return array[Math.floor(Math.random() * array.length)];
}

function randomElements<T>(array: T[], count: number): T[] {
  const result = [];
  const copy = [...array];
  for (let i = 0; i < Math.min(count, copy.length); i++) {
    const idx = Math.floor(Math.random() * copy.length);
    result.push(copy[idx]);
    copy.splice(idx, 1);
  }
  return result;
}

function generateId(prefix: string): string {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

export function generateMockAlert(): Alert {
  const severity = Math.random() > 0.7 ? 'critical' : Math.random() > 0.5 ? 'high' : Math.random() > 0.3 ? 'medium' : 'low';
  return {
    id: generateId('ALT'),
    severity,
    title: randomElement(alertTitles),
    description: `Automated detection triggered based on security rules and behavioral analysis. Multiple indicators of compromise detected on affected assets.`,
    source: randomElement(alertSources),
    timestamp: new Date(Date.now() - Math.random() * 86400000),
    status: randomElement(['new', 'acknowledged', 'investigating']),
    affectedAssets: randomElements(affectedAssets, Math.floor(Math.random() * 3) + 1),
    mitreTactics: randomElements(mitreTactics, Math.floor(Math.random() * 3) + 1),
  };
}

export function generateMockIncident(): Incident {
  const severity = Math.random() > 0.6 ? 'critical' : Math.random() > 0.4 ? 'high' : 'medium';
  const createdAt = new Date(Date.now() - Math.random() * 7 * 86400000);
  return {
    id: generateId('INC'),
    title: `${severity.toUpperCase()} - ${randomElement(alertTitles)}`,
    severity,
    status: randomElement(['open', 'investigating', 'contained']),
    createdAt,
    lastUpdated: new Date(createdAt.getTime() + Math.random() * 86400000),
    affectedSystems: randomElements(affectedAssets, Math.floor(Math.random() * 4) + 1),
    investigator: randomElement(users).name,
    description: 'Multi-stage attack with initial compromise through phishing, followed by credential theft and lateral movement.',
    evidenceCount: Math.floor(Math.random() * 20) + 5,
    relatedAlerts: Array.from({ length: Math.floor(Math.random() * 5) + 1 }).map(() => generateId('ALT')),
  };
}

function generateSingleThreatIntel(): ThreatIntel {
  const type = randomElement(['malware', 'ioc', 'vulnerability', 'campaign'] as const);
  return {
    id: generateId('THR'),
    type,
    title: `${type.toUpperCase()} - ${randomElement(companies)} Threat Campaign`,
    severity: Math.random() > 0.5 ? 'critical' : Math.random() > 0.3 ? 'high' : 'medium',
    description: 'New threat actor campaign targeting critical infrastructure in financial sector.',
    indicators: Array.from({ length: Math.floor(Math.random() * 5) + 3 }).map(() => `${Math.random().toString(36).substr(2, 12)}.${Math.random().toString(36).substr(2, 4)}`),
    lastSeen: new Date(Date.now() - Math.random() * 7 * 86400000),
    confidence: Math.floor(Math.random() * 40) + 60,
  };
}

export function generateMockDevice(): Device {
  const statuses: Array<'healthy' | 'compromised' | 'at-risk' | 'quarantined'> = ['healthy', 'compromised', 'at-risk', 'quarantined'];
  const status = Math.random() > 0.8 ? statuses[Math.floor(Math.random() * 4)] : 'healthy';
  return {
    id: generateId('DEV'),
    name: randomElement(affectedAssets),
    osType: randomElement(['Windows Server 2022', 'Windows 10', 'Ubuntu 22.04', 'macOS Ventura', 'RHEL 8']),
    lastSeen: new Date(Date.now() - Math.random() * 86400000),
    status,
    riskScore: status === 'healthy' ? Math.random() * 30 : Math.random() * 100,
    alertCount: Math.floor(Math.random() * 25),
    owner: randomElement(users).name,
  };
}

export function generateMockUser(): User {
  const user = randomElement(users);
  return {
    id: generateId('USR'),
    name: user.name,
    email: user.email,
    department: user.department,
    lastActive: new Date(Date.now() - Math.random() * 86400000),
    riskLevel: Math.random() > 0.9 ? 'critical' : Math.random() > 0.7 ? 'high' : 'low',
    alertCount: Math.floor(Math.random() * 15),
  };
}

export function generateMockAlerts(count: number): Alert[] {
  return Array.from({ length: count }).map(() => generateMockAlert());
}

export function generateMockIncidents(count: number): Incident[] {
  return Array.from({ length: count }).map(() => generateMockIncident());
}

export function generateMockThreatIntel(count: number): ThreatIntel[] {
  return Array.from({ length: count }).map(() => generateSingleThreatIntel());
}

export function generateMockDevices(count: number): Device[] {
  return Array.from({ length: count }).map(() => generateMockDevice());
}

export function generateMockUsers(count: number): User[] {
  return Array.from({ length: count }).map(() => generateMockUser());
}

// Real-time simulation data
export function generateRealtimeMetrics() {
  return {
    alertsPerSecond: Math.floor(Math.random() * 15) + 2,
    incidentsOpen: Math.floor(Math.random() * 45) + 15,
    devicesAtRisk: Math.floor(Math.random() * 25) + 5,
    detectionRate: Math.floor(Math.random() * 15) + 85,
    avgResponseTime: Math.floor(Math.random() * 120) + 30,
    threatLevel: ['low', 'medium', 'high', 'critical'][Math.floor(Math.random() * 4)],
  };
}

// Asset inventory
export const mockAssets = {
  devices: generateMockDevices(12),
  users: generateMockUsers(8),
  alerts: generateMockAlerts(50),
  incidents: generateMockIncidents(15),
  threatIntel: generateMockThreatIntel(20),
};
