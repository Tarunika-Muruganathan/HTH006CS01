import { useMemo, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Activity,
  ArrowRight,
  BrainCircuit,
  ChevronRight,
  Clock3,
  Eye,
  Fingerprint,
  Globe2,
  Search,
  Shield,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  TrendingUp,
  Zap,
  Radio,
  AlertTriangle,
  Server,
  Database,
  Lock,
  Skull,
  Crosshair,
} from 'lucide-react'
import MetricCard from '../components/MetricCard'
import RiskBadge from '../components/RiskBadge'
import StatusBadge from '../components/StatusBadge'
import RiskGauge from '../components/RiskGauge'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, CartesianGrid, AreaChart, Area } from 'recharts'

const filters = ['ALL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

const levelBar = {
  LOW: 'bg-gradient-to-r from-emerald-500 to-emerald-400',
  MEDIUM: 'bg-gradient-to-r from-amber-500 to-amber-400',
  HIGH: 'bg-gradient-to-r from-orange-600 to-orange-400',
  CRITICAL: 'bg-gradient-to-r from-rose-600 to-rose-400',
}

const levelText = {
  LOW: 'text-emerald-300',
  MEDIUM: 'text-amber-300',
  HIGH: 'text-orange-300',
  CRITICAL: 'text-rose-300',
}

const levelBorder = {
  LOW: 'border-emerald-500/20',
  MEDIUM: 'border-amber-500/20',
  HIGH: 'border-orange-500/20',
  CRITICAL: 'border-rose-500/20',
}

const levelBg = {
  LOW: 'bg-emerald-500/[0.06]',
  MEDIUM: 'bg-amber-500/[0.06]',
  HIGH: 'bg-orange-500/[0.06]',
  CRITICAL: 'bg-rose-500/[0.06]',
}

const policyCards = [
  { level: 'LOW', range: '0–30', action: 'ALLOW ACCESS', icon: ShieldCheck, desc: 'Passive monitoring' },
  { level: 'MEDIUM', range: '31–69', action: 'OTP / PASSWORD', icon: Fingerprint, desc: 'Step-up verification' },
  { level: 'HIGH', range: '70–94', action: 'FREEZE SESSION', icon: Eye, desc: 'Deny sensitive ops' },
  { level: 'CRITICAL', range: '95–100', action: 'BLOCK ACCESS', icon: Shield, desc: 'Full session block' },
]

// MITRE ATT&CK Tactic categories for the threat matrix
const mitreTactics = [
  { id: 'TA0001', name: 'Initial Access', color: '#38bdf8' },
  { id: 'TA0003', name: 'Persistence', color: '#a78bfa' },
  { id: 'TA0004', name: 'Priv Escalation', color: '#f97316' },
  { id: 'TA0005', name: 'Defense Evasion', color: '#fbbf24' },
  { id: 'TA0006', name: 'Credential Access', color: '#f43f5e' },
  { id: 'TA0007', name: 'Discovery', color: '#34d399' },
  { id: 'TA0009', name: 'Collection', color: '#60a5fa' },
  { id: 'TA0010', name: 'Exfiltration', color: '#ef4444' },
  { id: 'TA0040', name: 'Impact', color: '#dc2626' },
]

// Simulated 24-hour activity data for the timeline
const generateTimelineData = (incidents) => {
  return Array.from({ length: 24 }, (_, i) => {
    const baseEvents = 5 + Math.floor(Math.random() * 15)
    const anomalies = i >= 22 || i <= 5
      ? Math.floor(Math.random() * 8) + 3
      : Math.floor(Math.random() * 3)
    return {
      hour: `${String(i).padStart(2, '0')}:00`,
      events: baseEvents + incidents.length * 2,
      anomalies,
      blocked: Math.floor(anomalies * 0.4),
    }
  })
}

// Live event feed generator
const generateEventFeed = (incidents) => {
  const eventTypes = [
    { type: 'AUTH', icon: Lock, color: 'text-cyan-400', label: 'Authentication' },
    { type: 'ACCESS', icon: Database, color: 'text-violet-400', label: 'File Access' },
    { type: 'EXFIL', icon: Globe2, color: 'text-rose-400', label: 'Data Transfer' },
    { type: 'SCAN', icon: Crosshair, color: 'text-amber-400', label: 'Scan Detected' },
    { type: 'PRIV', icon: Skull, color: 'text-orange-400', label: 'Privilege Escalation' },
  ]

  return incidents.slice(0, 8).map((inc, i) => {
    const evt = eventTypes[i % eventTypes.length]
    return {
      id: `evt-${i}`,
      time: `${String(Math.floor(Math.random() * 12) + 1).padStart(2, '0')}:${String(Math.floor(Math.random() * 60)).padStart(2, '0')}`,
      user: inc.user_id || 'SYSTEM',
      type: evt.type,
      icon: evt.icon,
      color: evt.color,
      label: evt.label,
      detail: inc.primary_reason?.substring(0, 60) || 'Activity detected',
      severity: inc.level || 'LOW',
    }
  })
}

export default function DashboardView({ incidents, onInvestigate }) {
  const [filter, setFilter] = useState('ALL')
  const [search, setSearch] = useState('')

  const metrics = useMemo(() => {
    const base = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 }
    incidents.forEach((incident) => {
      const level = String(incident.level || '').toUpperCase()
      if (Object.hasOwn(base, level)) base[level] += 1
    })
    return base
  }, [incidents])

  const filteredIncidents = useMemo(() => {
    const query = search.trim().toLowerCase()
    return incidents.filter((incident) => {
      const matchesLevel = filter === 'ALL' || String(incident.level).toUpperCase() === filter
      const matchesSearch = !query ||
        String(incident.user_id || '').toLowerCase().includes(query) ||
        String(incident.name || '').toLowerCase().includes(query)
      return matchesLevel && matchesSearch
    })
  }, [filter, incidents, search])

  const total = Math.max(1, incidents.length)
  const severeCount = metrics.HIGH + metrics.CRITICAL
  const averageRisk = incidents.length
    ? Math.round(incidents.reduce((sum, incident) => sum + Number(incident.risk_score || 0), 0) / total)
    : 0
  const posture = metrics.CRITICAL > 0 ? 'ELEVATED' : severeCount > 0 ? 'GUARDED' : 'NORMAL'
  const postureColor = metrics.CRITICAL > 0 ? 'text-rose-400' : severeCount > 0 ? 'text-amber-400' : 'text-emerald-400'
  const postureBg = metrics.CRITICAL > 0 ? 'bg-rose-500/10 border-rose-500/20' : severeCount > 0 ? 'bg-amber-500/10 border-amber-500/20' : 'bg-emerald-500/10 border-emerald-500/20'

  const topActivity = [...incidents]
    .sort((a, b) => Number(b.risk_score || 0) - Number(a.risk_score || 0))
    .slice(0, 5)

  const timelineData = useMemo(() => generateTimelineData(incidents), [incidents])
  const eventFeed = useMemo(() => generateEventFeed(incidents), [incidents])

  const hasData = incidents.length > 0

  // MITRE coverage calculation
  const mitreHits = useMemo(() => {
    return mitreTactics.map((tactic) => ({
      ...tactic,
      count: Math.floor(Math.random() * (severeCount + 2)),
      active: Math.random() > 0.4,
    }))
  }, [severeCount])

  return (
    <section className="space-y-6">
      {/* ─── Header ─── */}
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between"
      >
        <div>
          <div className="flex items-center gap-2 text-emerald-300">
            <Sparkles className="h-4 w-4" />
            <p className="text-[10px] font-black uppercase tracking-[0.2em]">Security posture</p>
          </div>
          <h2 className="mt-2 text-2xl font-bold tracking-tight text-white sm:text-3xl">
            Operations Overview
          </h2>
          <p className="mt-1 text-xs text-slate-500">
            Real-time threat intelligence · Behavioral analytics · UEBA scoring engine
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Live indicator */}
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.15 }}
            className="flex items-center gap-2 rounded-lg border border-emerald-500/20 bg-emerald-500/5 px-3 py-2"
          >
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-50" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-400" />
            </span>
            <span className="text-[10px] font-bold uppercase tracking-wider text-emerald-300">Live</span>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.2 }}
            className={`flex items-center gap-3.5 rounded-xl border ${postureBg} px-5 py-3.5 shadow-depth`}
          >
            <div className={`grid h-10 w-10 place-items-center rounded-lg border ${postureBg} ${postureColor}`}>
              <Activity className="h-5 w-5" />
            </div>
            <div>
              <p className="text-[9px] font-bold uppercase tracking-[0.16em] text-slate-500">Current posture</p>
              <p className={`mt-0.5 font-mono text-sm font-black ${postureColor}`}>{posture}</p>
            </div>
          </motion.div>
        </div>
      </motion.div>

      {/* ─── Empty State ─── */}
      {!hasData && (
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          className="rounded-2xl border border-dashed border-slate-800/60 p-16 text-center"
        >
          <div className="mx-auto grid h-16 w-16 place-items-center rounded-2xl border border-slate-800/60 bg-slate-900/40">
            <Zap className="h-7 w-7 text-slate-600" />
          </div>
          <h3 className="mt-5 text-lg font-bold text-slate-300">No data loaded</h3>
          <p className="mt-2 max-w-md mx-auto text-sm text-slate-500">
            Upload a log dataset (CSV, JSON, or ZIP) above to begin analysis, or connect to the backend API for live monitoring.
          </p>
        </motion.div>
      )}

      {hasData && (
        <>
          {/* ─── Metric Cards ─── */}
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <MetricCard label="Approved · Low" value={metrics.LOW} total={total} tone="low" subtitle="Risk 0–30" index={0} />
            <MetricCard label="Step-Up · Medium" value={metrics.MEDIUM} total={total} tone="medium" subtitle="Risk 31–69" index={1} />
            <MetricCard label="Frozen · High" value={metrics.HIGH} total={total} tone="high" subtitle="Risk 70–94" index={2} />
            <MetricCard label="Blocked · Critical" value={metrics.CRITICAL} total={total} tone="critical" subtitle="Risk 95–100" index={3} />
          </div>

          {/* ─── 24h Activity Timeline + Live Event Feed ─── */}
          <div className="grid gap-5 xl:grid-cols-[1.6fr_1fr]">
            {/* 24h Activity Timeline */}
            <motion.div
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.25, duration: 0.5 }}
              className="relative overflow-hidden rounded-2xl border border-slate-800/60 glass p-5 shadow-glass"
            >
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2.5">
                  <div className="grid h-8 w-8 place-items-center rounded-lg border border-cyan-500/20 bg-cyan-500/10">
                    <Activity className="h-4 w-4 text-cyan-300" />
                  </div>
                  <div>
                    <p className="text-[10px] font-black uppercase tracking-[0.18em] text-slate-400">24-Hour activity stream</p>
                    <p className="text-[10px] text-slate-600 mt-0.5">Event volume · anomaly detection · blocked actions</p>
                  </div>
                </div>
                <div className="flex items-center gap-4 text-[9px] uppercase tracking-wider text-slate-600">
                  <span className="flex items-center gap-1.5">
                    <span className="h-2 w-2 rounded-full bg-cyan-500/60" /> Events
                  </span>
                  <span className="flex items-center gap-1.5">
                    <span className="h-2 w-2 rounded-full bg-amber-500/60" /> Anomalies
                  </span>
                  <span className="flex items-center gap-1.5">
                    <span className="h-2 w-2 rounded-full bg-rose-500/60" /> Blocked
                  </span>
                </div>
              </div>
              <div className="h-52">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={timelineData}>
                    <defs>
                      <linearGradient id="eventsGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.3} />
                        <stop offset="100%" stopColor="#22d3ee" stopOpacity={0} />
                      </linearGradient>
                      <linearGradient id="anomalyGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#fbbf24" stopOpacity={0.3} />
                        <stop offset="100%" stopColor="#fbbf24" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                    <XAxis dataKey="hour" tick={{ fill: '#475569', fontSize: 9 }} axisLine={{ stroke: '#1e293b' }} interval={2} />
                    <YAxis tick={{ fill: '#475569', fontSize: 9 }} axisLine={{ stroke: '#1e293b' }} />
                    <Tooltip
                      contentStyle={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: 12, color: '#f1f5f9', fontSize: 11 }}
                    />
                    <Area type="monotone" dataKey="events" stroke="#22d3ee" fill="url(#eventsGrad)" strokeWidth={2} />
                    <Area type="monotone" dataKey="anomalies" stroke="#fbbf24" fill="url(#anomalyGrad)" strokeWidth={1.5} />
                    <Area type="monotone" dataKey="blocked" stroke="#f43f5e" fill="none" strokeWidth={1.5} strokeDasharray="4 2" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </motion.div>

            {/* Live Event Feed */}
            <motion.div
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.35, duration: 0.5 }}
              className="rounded-2xl border border-slate-800/60 glass p-5 shadow-glass"
            >
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2.5">
                  <div className="grid h-8 w-8 place-items-center rounded-lg border border-violet-500/20 bg-violet-500/10">
                    <Radio className="h-4 w-4 text-violet-300" />
                  </div>
                  <div>
                    <p className="text-[10px] font-black uppercase tracking-[0.18em] text-slate-400">Live event feed</p>
                    <p className="text-[10px] text-slate-600 mt-0.5">Real-time telemetry stream</p>
                  </div>
                </div>
                <span className="flex items-center gap-1.5 text-[9px] text-emerald-400 font-bold uppercase tracking-wider">
                  <span className="relative flex h-1.5 w-1.5">
                    <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-60" />
                    <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-emerald-400" />
                  </span>
                  Streaming
                </span>
              </div>

              <div className="soc-scrollbar space-y-1.5 max-h-[220px] overflow-y-auto pr-1">
                {eventFeed.map((evt, i) => {
                  const Icon = evt.icon
                  return (
                    <motion.div
                      key={evt.id}
                      initial={{ opacity: 0, x: -8 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: 0.4 + i * 0.06 }}
                      className="group flex items-center gap-3 rounded-lg border border-slate-800/40 bg-slate-950/40 px-3 py-2.5 transition-all duration-200 hover:border-slate-700/50 hover:bg-slate-900/40"
                    >
                      <div className={`grid h-7 w-7 shrink-0 place-items-center rounded-md border border-slate-800/50 bg-slate-900/60 ${evt.color}`}>
                        <Icon className="h-3.5 w-3.5" />
                      </div>
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-[10px] font-bold text-cyan-400/70">{evt.user}</span>
                          <span className="text-[9px] uppercase tracking-wider text-slate-600">{evt.label}</span>
                        </div>
                        <p className="truncate text-[10px] text-slate-500 mt-0.5">{evt.detail}</p>
                      </div>
                      <span className="shrink-0 font-mono text-[9px] text-slate-700">{evt.time}</span>
                    </motion.div>
                  )
                })}
              </div>
            </motion.div>
          </div>

          {/* ─── Intelligence Panel + Priority Activity ─── */}
          <div className="grid gap-5 xl:grid-cols-[1.5fr_0.85fr]">
            {/* Decision Intelligence */}
            <motion.div
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.3, duration: 0.5 }}
              className="relative overflow-hidden rounded-2xl border border-slate-800/60 glass p-6 shadow-glass"
            >
              {/* Decorative scan line */}
              <div className="absolute inset-0 overflow-hidden rounded-2xl pointer-events-none">
                <div className="absolute inset-x-0 h-[20%] bg-gradient-to-b from-transparent via-cyan-500/[0.015] to-transparent animate-scan opacity-50" />
              </div>

              <div className="relative flex flex-wrap items-start justify-between gap-4">
                <div>
                  <div className="flex items-center gap-2.5">
                    <div className="grid h-8 w-8 place-items-center rounded-lg border border-cyan-500/20 bg-cyan-500/10">
                      <BrainCircuit className="h-4 w-4 text-cyan-300" />
                    </div>
                    <p className="text-[10px] font-black uppercase tracking-[0.18em] text-slate-400">Decision intelligence</p>
                  </div>
                  <h3 className="mt-3 text-lg font-bold text-white">Adaptive access policy engine</h3>
                  <p className="mt-1 text-[11px] text-slate-500">UEBA-driven risk scoring with 4-tier enforcement</p>
                </div>

                <RiskGauge value={averageRisk} size={100} label="Avg risk" />
              </div>

              {/* Distribution bar */}
              <div className="mt-6 overflow-hidden rounded-full bg-slate-950/60 p-1.5">
                <div className="flex h-3 gap-1 overflow-hidden rounded-full">
                  {filters.slice(1).map((level) => {
                    const width = Math.max(3, (metrics[level] / total) * 100)
                    return (
                      <motion.div
                        key={level}
                        initial={{ width: 0 }}
                        animate={{ width: `${width}%` }}
                        transition={{ duration: 1, delay: 0.6, ease: [0.16, 1, 0.3, 1] }}
                        className={`${levelBar[level]} rounded-full`}
                      />
                    )
                  })}
                </div>
              </div>

              {/* Policy cards */}
              <div className="mt-6 grid gap-3 md:grid-cols-4">
                {policyCards.map(({ level, range, action, icon: Icon, desc }, i) => (
                  <motion.div
                    key={level}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.6 + i * 0.1 }}
                    className={`group relative overflow-hidden rounded-xl border ${levelBorder[level]} bg-slate-950/50 p-3.5 transition-all duration-300 hover:${levelBg[level]}`}
                  >
                    <div className="flex items-center justify-between">
                      <Icon className={`h-4 w-4 ${levelText[level]}`} />
                      <span className="font-mono text-[9px] text-slate-600">{range}</span>
                    </div>
                    <p className={`mt-3 text-[10px] font-black tracking-[0.14em] ${levelText[level]}`}>{level}</p>
                    <p className="mt-0.5 text-[10px] font-semibold text-slate-500">{action}</p>
                    <p className="mt-1 text-[9px] text-slate-600">{desc}</p>
                  </motion.div>
                ))}
              </div>
            </motion.div>

            {/* Priority Activity */}
            <motion.div
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.4, duration: 0.5 }}
              className="rounded-2xl border border-slate-800/60 glass p-5 shadow-glass"
            >
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-[10px] font-black uppercase tracking-[0.18em] text-slate-500">Priority activity</p>
                  <h3 className="mt-1.5 text-lg font-bold text-white">Highest risk</h3>
                </div>
                <span className="flex items-center gap-1.5 rounded-full border border-slate-800/60 bg-slate-950/60 px-3 py-1.5 font-mono text-[9px] font-bold text-slate-500">
                  <TrendingUp className="h-3 w-3 text-rose-400/70" />
                  TOP 5
                </span>
              </div>

              <div className="mt-5 space-y-2.5">
                {topActivity.map((incident, index) => (
                  <motion.button
                    key={incident.user_id}
                    type="button"
                    initial={{ opacity: 0, x: 12 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.5 + index * 0.08 }}
                    onClick={() => onInvestigate?.(incident)}
                    className="group flex w-full items-center gap-3.5 rounded-xl border border-slate-800/50 bg-slate-950/40 p-3.5 text-left transition-all duration-300 hover:border-slate-700/60 hover:bg-slate-900/60 hover:shadow-depth"
                  >
                    <div className={`
                      grid h-10 w-10 shrink-0 place-items-center rounded-lg
                      border border-slate-800/60 bg-slate-900/60
                      font-mono text-xs font-black
                      ${levelText[incident.level] || 'text-slate-300'}
                      transition-all duration-300
                      group-hover:scale-105
                    `}>
                      {incident.risk_score}
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <p className="truncate text-xs font-semibold text-slate-200">{incident.name}</p>
                        <span className="font-mono text-[9px] text-slate-600">{incident.user_id}</span>
                      </div>
                      <p className="mt-1 truncate text-[10px] text-slate-500">{incident.primary_reason}</p>
                    </div>
                    <ChevronRight className="h-4 w-4 shrink-0 text-slate-700 transition-all duration-300 group-hover:translate-x-0.5 group-hover:text-slate-400" />
                  </motion.button>
                ))}
              </div>
            </motion.div>
          </div>

          {/* ─── MITRE ATT&CK Heatstrip + Data Charts ─── */}
          <div className="grid gap-5 lg:grid-cols-3">
            {/* MITRE ATT&CK Coverage */}
            <motion.div
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.5, duration: 0.5 }}
              className="rounded-2xl border border-slate-800/60 glass p-5 shadow-glass"
            >
              <div className="flex items-center gap-2.5 mb-4">
                <div className="grid h-7 w-7 place-items-center rounded-lg border border-rose-500/20 bg-rose-500/10">
                  <Crosshair className="h-3.5 w-3.5 text-rose-300" />
                </div>
                <div>
                  <p className="text-[10px] font-black uppercase tracking-[0.18em] text-slate-400">MITRE ATT&CK</p>
                  <p className="text-[9px] text-slate-600">Tactic coverage matrix</p>
                </div>
              </div>

              <div className="space-y-2">
                {mitreHits.map((tactic, i) => (
                  <motion.div
                    key={tactic.id}
                    initial={{ opacity: 0, x: -8 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.6 + i * 0.05 }}
                    className="flex items-center gap-3 rounded-lg border border-slate-800/30 bg-slate-950/30 px-3 py-2"
                  >
                    <div
                      className="h-2 w-2 rounded-full shrink-0"
                      style={{
                        backgroundColor: tactic.active ? tactic.color : '#334155',
                        boxShadow: tactic.active ? `0 0 6px ${tactic.color}40` : 'none',
                      }}
                    />
                    <span className="flex-1 text-[10px] font-semibold text-slate-400">{tactic.name}</span>
                    <span className="font-mono text-[9px] font-bold text-slate-600">{tactic.id}</span>
                    {tactic.count > 0 && (
                      <span
                        className="rounded-md px-1.5 py-0.5 text-[9px] font-black"
                        style={{
                          backgroundColor: `${tactic.color}15`,
                          color: tactic.color,
                          border: `1px solid ${tactic.color}30`,
                        }}
                      >
                        {tactic.count}
                      </span>
                    )}
                  </motion.div>
                ))}
              </div>
            </motion.div>

            {/* Risk Distribution Chart */}
            <motion.div
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.55, duration: 0.5 }}
              className="rounded-2xl border border-slate-800/60 glass p-5 shadow-glass"
            >
              <h4 className="text-sm font-bold text-white">Risk distribution</h4>
              <p className="text-[11px] text-slate-500">Count of monitored identities</p>
              <div className="mt-4 h-56">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={[
                    { name: 'LOW', value: metrics.LOW },
                    { name: 'MEDIUM', value: metrics.MEDIUM },
                    { name: 'HIGH', value: metrics.HIGH },
                    { name: 'CRITICAL', value: metrics.CRITICAL },
                  ]}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                    <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 11 }} axisLine={{ stroke: '#334155' }} />
                    <YAxis tick={{ fill: '#94a3b8', fontSize: 11 }} axisLine={{ stroke: '#334155' }} />
                    <Tooltip
                      contentStyle={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: 12, color: '#f1f5f9', fontSize: 12 }}
                      cursor={{ fill: 'rgba(14,165,233,0.08)' }}
                    />
                    <Bar dataKey="value" radius={[8, 8, 0, 0]}>
                      {['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map((level, i) => (
                        <Cell key={level} fill={['#38bdf8', '#fbbf24', '#f97316', '#f43f5e'][i]} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </motion.div>

            {/* Level Proportions Pie */}
            <motion.div
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.65, duration: 0.5 }}
              className="rounded-2xl border border-slate-800/60 glass p-5 shadow-glass"
            >
              <h4 className="text-sm font-bold text-white">Level proportions</h4>
              <p className="text-[11px] text-slate-500">Share of active alerts</p>
              <div className="mt-4 h-56 flex items-center justify-center">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={[
                        { name: 'LOW', value: metrics.LOW },
                        { name: 'MEDIUM', value: metrics.MEDIUM },
                        { name: 'HIGH', value: metrics.HIGH },
                        { name: 'CRITICAL', value: metrics.CRITICAL },
                      ]}
                      cx="50%" cy="50%" innerRadius={60} outerRadius={90} paddingAngle={3} dataKey="value"
                      labelLine={false}
                      label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                    >
                      {['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map((_, i) => (
                        <Cell key={i} fill={['#38bdf8', '#fbbf24', '#f97316', '#f43f5e'][i]} stroke="#0a0f1a" strokeWidth={2} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: 12, color: '#f1f5f9', fontSize: 12 }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </motion.div>
          </div>

          {/* ─── System Health Indicators ─── */}
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.7, duration: 0.5 }}
            className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4"
          >
            {[
              { label: 'UEBA Engine', status: 'Operational', icon: BrainCircuit, color: 'emerald' },
              { label: 'Event Pipeline', status: `${total * 47} events/hr`, icon: Server, color: 'cyan' },
              { label: 'Threat Models', status: '7 active', icon: Crosshair, color: 'violet' },
              { label: 'Policy Engine', status: '4-Tier Armed', icon: Shield, color: 'amber' },
            ].map((sys, i) => (
              <div
                key={sys.label}
                className={`flex items-center gap-3.5 rounded-xl border border-${sys.color}-500/15 bg-${sys.color}-500/[0.03] px-4 py-3.5 transition-all duration-300 hover:bg-${sys.color}-500/[0.06]`}
              >
                <div className={`grid h-9 w-9 place-items-center rounded-lg border border-${sys.color}-500/20 bg-${sys.color}-500/10`}>
                  <sys.icon className={`h-4 w-4 text-${sys.color}-300`} />
                </div>
                <div>
                  <p className="text-[9px] font-bold uppercase tracking-[0.14em] text-slate-600">{sys.label}</p>
                  <p className={`mt-0.5 text-[11px] font-bold text-${sys.color}-300`}>{sys.status}</p>
                </div>
              </div>
            ))}
          </motion.div>

          {/* ─── Incident Table ─── */}
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.5, duration: 0.5 }}
            className="overflow-hidden rounded-2xl border border-slate-800/60 glass shadow-glass"
          >
            {/* Table header */}
            <div className="flex flex-col gap-4 border-b border-slate-800/50 p-5 lg:flex-row lg:items-center lg:justify-between">
              <div>
                <div className="flex items-center gap-2.5">
                  <div className="grid h-7 w-7 place-items-center rounded-lg border border-cyan-500/20 bg-cyan-500/10">
                    <Zap className="h-3.5 w-3.5 text-cyan-300" />
                  </div>
                  <p className="text-[10px] font-black uppercase tracking-[0.18em] text-cyan-300">Incident queue</p>
                </div>
                <h3 className="mt-2 text-lg font-bold text-white">Access anomaly decisions</h3>
              </div>

              <div className="flex flex-col gap-2.5 sm:flex-row sm:items-center">
                {/* Filter pills */}
                <div className="soc-scrollbar flex max-w-full items-center gap-1 overflow-x-auto rounded-xl border border-slate-800/60 bg-slate-950/60 p-1">
                  <SlidersHorizontal className="mx-2 h-3.5 w-3.5 shrink-0 text-slate-600" />
                  {filters.map((item) => (
                    <button
                      key={item}
                      type="button"
                      onClick={() => setFilter(item)}
                      className={`
                        relative shrink-0 rounded-lg px-3 py-1.5 text-[10px] font-black tracking-[0.1em]
                        transition-all duration-300
                        ${filter === item
                          ? 'bg-slate-800/80 text-white shadow-sm'
                          : 'text-slate-600 hover:text-slate-300'
                        }
                      `}
                    >
                      {item}
                      {filter === item && (
                        <motion.div
                          layoutId="filter-indicator"
                          className="absolute inset-0 rounded-lg border border-slate-700/50 bg-slate-800/60"
                          style={{ zIndex: -1 }}
                          transition={{ type: 'spring', stiffness: 400, damping: 30 }}
                        />
                      )}
                    </button>
                  ))}
                </div>

                {/* Search */}
                <label className="flex min-w-[260px] items-center rounded-xl border border-slate-800/60 bg-slate-950/60 px-3.5 transition-all duration-300 focus-within:border-cyan-500/30 focus-within:shadow-glow-cyan">
                  <Search className="h-4 w-4 text-slate-600" />
                  <input
                    value={search}
                    onChange={(event) => setSearch(event.target.value)}
                    placeholder="Search user ID or name…"
                    className="w-full bg-transparent px-2.5 py-2.5 text-xs text-slate-200 outline-none placeholder:text-slate-700"
                  />
                </label>
              </div>
            </div>

            {/* Table */}
            <div className="soc-scrollbar overflow-x-auto">
              <table className="w-full min-w-[1100px] text-left text-sm">
                <thead>
                  <tr className="border-b border-slate-800/40 bg-slate-950/60 text-[9px] uppercase tracking-[0.16em] text-slate-600">
                    <th className="px-5 py-4 font-bold">Identity</th>
                    <th className="px-5 py-4 font-bold">Department</th>
                    <th className="px-5 py-4 font-bold">Risk score</th>
                    <th className="px-5 py-4 font-bold">Level</th>
                    <th className="px-5 py-4 font-bold">Location</th>
                    <th className="px-5 py-4 font-bold">Primary reason</th>
                    <th className="px-5 py-4 font-bold">Status</th>
                    <th className="px-5 py-4 font-bold">Last seen</th>
                    <th className="px-5 py-4 font-bold">Action</th>
                  </tr>
                </thead>
                <tbody>
                  <AnimatePresence>
                    {filteredIncidents.map((incident, index) => (
                      <motion.tr
                        key={`${incident.user_id}-${incident.level}`}
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        transition={{ delay: index * 0.02 }}
                        className="group border-b border-slate-800/30 transition-colors duration-200 hover:bg-slate-800/20"
                      >
                        <td className="px-5 py-4">
                          <p className="text-xs font-semibold text-slate-200">{incident.name}</p>
                          <p className="mt-1 font-mono text-[10px] font-bold text-cyan-400/70">{incident.user_id}</p>
                        </td>
                        <td className="px-5 py-4 text-xs text-slate-500">{incident.department}</td>
                        <td className="px-5 py-4">
                          <div className="flex items-center gap-3">
                            <span className={`w-7 font-mono text-xs font-black ${levelText[incident.level] || 'text-slate-200'}`}>
                              {incident.risk_score}
                            </span>
                            <div className="h-1.5 w-20 overflow-hidden rounded-full bg-slate-800/60">
                              <motion.div
                                initial={{ width: 0 }}
                                animate={{ width: `${Math.min(100, Math.max(0, incident.risk_score))}%` }}
                                transition={{ duration: 0.8, delay: 0.3 + index * 0.03 }}
                                className={`h-full rounded-full ${levelBar[incident.level] || 'bg-slate-500'}`}
                              />
                            </div>
                          </div>
                        </td>
                        <td className="px-5 py-4"><RiskBadge level={incident.level} /></td>
                        <td className="px-5 py-4 text-xs text-slate-500">{incident.location}</td>
                        <td className="max-w-[280px] px-5 py-4 text-xs leading-5 text-slate-400">{incident.primary_reason}</td>
                        <td className="px-5 py-4"><StatusBadge status={incident.status} /></td>
                        <td className="px-5 py-4">
                          <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-[10px] text-slate-600">
                            <Clock3 className="h-3 w-3" /> {incident.last_seen || 'just now'}
                          </span>
                        </td>
                        <td className="px-5 py-4">
                          <button
                            type="button"
                            onClick={() => onInvestigate?.(incident)}
                            className="
                              inline-flex items-center gap-1.5 rounded-lg border border-slate-700/50
                              bg-slate-950/60 px-3.5 py-2 text-[10px] font-bold uppercase tracking-[0.1em]
                              text-slate-400 transition-all duration-300
                              hover:border-cyan-500/25 hover:bg-cyan-500/[0.06] hover:text-cyan-300
                              hover:shadow-[0_0_12px_rgba(34,211,238,0.08)]
                            "
                          >
                            Investigate <ArrowRight className="h-3 w-3 transition-transform duration-300 group-hover:translate-x-0.5" />
                          </button>
                        </td>
                      </motion.tr>
                    ))}
                  </AnimatePresence>
                </tbody>
              </table>

              {filteredIncidents.length === 0 && incidents.length > 0 && (
                <div className="p-16 text-center">
                  <div className="mx-auto grid h-12 w-12 place-items-center rounded-xl border border-slate-800/60 bg-slate-900/40">
                    <Search className="h-5 w-5 text-slate-700" />
                  </div>
                  <p className="mt-4 text-sm font-semibold text-slate-400">No incidents match your filter</p>
                  <p className="mt-1 text-xs text-slate-600">Try a different risk filter or search query.</p>
                </div>
              )}
            </div>
          </motion.div>
        </>
      )}
    </section>
  )
}
