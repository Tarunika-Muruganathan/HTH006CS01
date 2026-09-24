const names = [
  'Aarav Sharma', 'Aditi Rao', 'Arjun Menon', 'Ananya Iyer', 'Dev Patel',
  'Diya Nair', 'Ethan George', 'Farhan Ali', 'Harini Kumar', 'Ishaan Verma',
  'Janani S', 'Karan Mehta', 'Kavya R', 'Lakshman P', 'Meera Krishnan',
  'Naveen Raj', 'Nikhil Das', 'Nithya M', 'Pranav Joshi', 'Priya S',
  'Rahul B', 'Riya Kapoor', 'Rohan Sen', 'Sanjana K', 'Siddharth Jain',
  'Sneha V', 'Surya Prakash', 'Tanvi Shah', 'Varun M', 'Vignesh R',
  'Vikram Anand', 'Yash Gupta', 'Zoya Khan', 'Mithran G', 'Keerthana P',
]

const departments = ['Engineering', 'Finance', 'HR', 'SOC', 'Sales', 'Operations', 'Legal']
const locations = ['Coimbatore HQ', 'Chennai Office', 'Bengaluru Office', 'Remote VPN', 'Hyderabad Office']

const baselineScore = (index) => [12, 19, 24, 28, 34, 42, 48, 55, 63, 72, 78, 86, 93][index % 13]

const levelForScore = (score) => {
  if (score <= 30) return 'LOW'
  if (score < 70) return 'MEDIUM'
  if (score < 95) return 'HIGH'
  return 'CRITICAL'
}

const statusForLevel = (level) => ({
  LOW: 'APPROVED',
  MEDIUM: 'VERIFYING',
  HIGH: 'FROZEN',
  CRITICAL: 'BLOCKED',
}[level])

const monitoredIds = [
  'EMP101', 'EMP124', 'EMP147', 'EMP170', 'EMP193', 'EMP205', 'EMP239',
  'EMP262', 'EMP285', 'EMP302', 'EMP331', 'EMP354', 'EMP377', 'EMP400',
  'EMP423', 'EMP446', 'EMP469', 'EMP492', 'EMP515', 'EMP538', 'EMP561',
  'EMP584', 'EMP607', 'EMP630', 'EMP653', 'EMP676', 'EMP699', 'EMP722',
  'EMP745', 'EMP768', 'EMP791', 'EMP814', 'EMP837', 'EMP860', 'EMP928',
]

export const monitoredUsers = names.map((name, index) => {
  const userId = monitoredIds[index]
  const score = baselineScore(index)
  const level = levelForScore(score)

  return {
    user_id: userId,
    name,
    department: departments[index % departments.length],
    risk_score: score,
    level,
    location: locations[index % locations.length],
    primary_reason:
      level === 'LOW'
        ? 'Behavior matches learned baseline'
        : level === 'MEDIUM'
          ? 'Unusual login time and device fingerprint'
          : level === 'HIGH'
            ? 'Sensitive resource access spike'
            : 'High-volume privileged data access',
    status: statusForLevel(level),
    last_seen: `${2 + (index % 8)} min ago`,
  }
})

const demoOverrides = {
  EMP101: {
    user_id: 'EMP101',
    name: 'Aarav Sharma',
    department: 'Engineering',
    risk_score: 18,
    level: 'LOW',
    location: 'Coimbatore HQ',
    primary_reason: 'Normal workstation and access pattern',
    status: 'APPROVED',
    last_seen: 'just now',
  },
  EMP205: {
    user_id: 'EMP205',
    name: 'Kavya R',
    department: 'Finance',
    risk_score: 54,
    level: 'MEDIUM',
    location: 'Remote VPN',
    primary_reason: 'New device + unusual access hour',
    status: 'VERIFYING',
    last_seen: 'just now',
  },
  EMP302: {
    user_id: 'EMP302',
    name: 'Rohan Sen',
    department: 'Operations',
    risk_score: 82,
    level: 'HIGH',
    location: 'Bengaluru Office',
    primary_reason: 'Abnormal sensitive-resource access burst',
    status: 'FROZEN',
    last_seen: 'just now',
  },
  EMP928: {
    user_id: 'EMP928',
    name: 'Zoya Khan',
    department: 'SOC',
    risk_score: 97,
    level: 'CRITICAL',
    location: 'Remote VPN',
    primary_reason: 'Privileged data exfiltration pattern detected',
    status: 'BLOCKED',
    last_seen: 'just now',
  },
}

export const demoIncidents = [
  demoOverrides.EMP928,
  demoOverrides.EMP302,
  demoOverrides.EMP205,
  demoOverrides.EMP101,
  ...monitoredUsers.filter(
    (user) => !['EMP101', 'EMP205', 'EMP302', 'EMP928'].includes(user.user_id),
  ),
].slice(0, 18)

export const getSimulationFallback = (type) => {
  const key = {
    normal: 'EMP101',
    medium: 'EMP205',
    high: 'EMP302',
    critical: 'EMP928',
  }[type]

  return { ...demoOverrides[key] }
}
