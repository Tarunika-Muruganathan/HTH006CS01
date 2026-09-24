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
  Search,
  Shield,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  TrendingUp,
  Zap,
} from 'lucide-react'
import MetricCard from '../components/MetricCard'
import RiskBadge from '../components/RiskBadge'
import StatusBadge from '../components/StatusBadge'
import RiskGauge from '../components/RiskGauge'

const filters = ['ALL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

const levelBar = {
  LOW: 'bg-gradient-to-r from-emerald-500 to-emerald-400',
  MEDIUM: 'bg-gradient-to-r from-amber-500 to-amber-400',
  HIGH: 'bg-gradient-to-r from-orange-600 to-orange-400',
  CRITICAL: 'bg-gradient-to-r from-rose-600 to-rose-400',
}

const levelBarSolid = {
  LOW: 'bg-emerald-400',
  MEDIUM: 'bg-amber-400',
  HIGH: 'bg-orange-500',
  CRITICAL: 'bg-rose-500',
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
  const averageRisk = Math.round(
    incidents.reduce((sum, incident) => sum + Number(incident.risk_score || 0), 0) / total,
  )
  const posture = metrics.CRITICAL > 0 ? 'ELEVATED' : severeCount > 0 ? 'GUARDED' : 'NORMAL'
  const postureColor = metrics.CRITICAL > 0 ? 'text-rose-400' : severeCount > 0 ? 'text-amber-400' : 'text-emerald-400'
  const postureBg = metrics.CRITICAL > 0 ? 'bg-rose-500/10 border-rose-500/20' : severeCount > 0 ? 'bg-amber-500/10 border-amber-500/20' : 'bg-emerald-500/10 border-emerald-500/20'

  const topActivity = [...incidents]
    .sort((a, b) => Number(b.risk_score || 0) - Number(a.risk_score || 0))
    .slice(0, 5)

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
            <p className="text-[10px] font-black uppercase tracking-[0.2em]">Live security posture</p>
          </div>
          <h2 className="mt-2 text-2xl font-bold tracking-tight text-white sm:text-3xl">
            SOC Operations Overview
          </h2>
          <p className="mt-1.5 max-w-2xl text-sm leading-relaxed text-slate-500">
            Explainable risk scoring, adaptive verification, and automated session enforcement in one control plane.
          </p>
        </div>

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
      </motion.div>

      {/* ─── Metric Cards ─── */}
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard label="Approved Access · Low" value={metrics.LOW} total={total} tone="low" subtitle="Risk score 0–30 · Allow" index={0} />
        <MetricCard label="Step-Up Required · Med" value={metrics.MEDIUM} total={total} tone="medium" subtitle="Risk score 31–69 · Verify" index={1} />
        <MetricCard label="Frozen Sessions · High" value={metrics.HIGH} total={total} tone="high" subtitle="Risk score 70–94 · Freeze" index={2} />
        <MetricCard label="Critical Blocks · Crit" value={metrics.CRITICAL} total={total} tone="critical" subtitle="Risk score 95–100 · Block" index={3} />
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
              <p className="mt-1 text-xs leading-relaxed text-slate-500">
                Every identity is routed to the minimum action required by its risk score.
              </p>
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
              <h3 className="mt-1.5 text-lg font-bold text-white">Highest risk now</h3>
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
              <p className="text-[10px] font-black uppercase tracking-[0.18em] text-cyan-300">Live incident queue</p>
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
          <table className="w-full min-w-[1320px] text-left text-sm">
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

          {filteredIncidents.length === 0 && (
            <div className="p-16 text-center">
              <div className="mx-auto grid h-12 w-12 place-items-center rounded-xl border border-slate-800/60 bg-slate-900/40">
                <Search className="h-5 w-5 text-slate-700" />
              </div>
              <p className="mt-4 text-sm font-semibold text-slate-400">No incidents found</p>
              <p className="mt-1 text-xs text-slate-600">Change the risk filter or search query.</p>
            </div>
          )}
        </div>
      </motion.div>
    </section>
  )
}
