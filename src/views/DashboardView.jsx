import { useMemo, useState } from 'react'
import {
  Activity,
  ArrowRight,
  BrainCircuit,
  Clock3,
  Eye,
  Fingerprint,
  Search,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
} from 'lucide-react'
import MetricCard from '../components/MetricCard'
import RiskBadge from '../components/RiskBadge'
import StatusBadge from '../components/StatusBadge'

const filters = ['ALL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

const levelBar = {
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
  const topActivity = [...incidents]
    .sort((a, b) => Number(b.risk_score || 0) - Number(a.risk_score || 0))
    .slice(0, 5)

  return (
    <section className="space-y-5">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <div className="flex items-center gap-2 text-emerald-300">
            <Sparkles className="h-4 w-4" />
            <p className="text-[10px] font-black uppercase tracking-[0.18em]">Live security posture</p>
          </div>
          <h2 className="mt-2 text-2xl font-bold tracking-tight text-slate-100 sm:text-3xl">SOC Operations Overview</h2>
          <p className="mt-1 max-w-2xl text-sm text-slate-500">
            Explainable risk scoring, adaptive verification, and automated session enforcement in one control plane.
          </p>
        </div>
        <div className="flex items-center gap-3 rounded-xl border border-slate-800 bg-slate-900/70 px-4 py-3">
          <div className="grid h-9 w-9 place-items-center rounded-lg border border-rose-500/20 bg-rose-500/10 text-rose-300">
            <Activity className="h-4 w-4" />
          </div>
          <div>
            <p className="text-[9px] font-bold uppercase tracking-[0.15em] text-slate-600">Current posture</p>
            <p className="mt-0.5 font-mono text-sm font-black text-rose-300">{posture}</p>
          </div>
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard label="Approved Access · Low" value={metrics.LOW} total={total} tone="low" subtitle="Risk score 0–30 · Allow" />
        <MetricCard label="Step-Up Required · Med" value={metrics.MEDIUM} total={total} tone="medium" subtitle="Risk score 31–69 · Verify" />
        <MetricCard label="Frozen Sessions · High" value={metrics.HIGH} total={total} tone="high" subtitle="Risk score 70–94 · Freeze" />
        <MetricCard label="Critical Blocks · Crit" value={metrics.CRITICAL} total={total} tone="critical" subtitle="Risk score 95–100 · Block" />
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.45fr_0.85fr]">
        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <div className="flex items-center gap-2 text-slate-300">
                <BrainCircuit className="h-4 w-4 text-cyan-300" />
                <p className="text-[10px] font-black uppercase tracking-[0.17em]">Decision intelligence</p>
              </div>
              <h3 className="mt-2 text-lg font-semibold text-slate-100">Adaptive access policy engine</h3>
              <p className="mt-1 text-xs text-slate-500">Every identity is routed to the minimum action required by its risk score.</p>
            </div>
            <div className="text-right">
              <p className="text-[9px] uppercase tracking-[0.15em] text-slate-600">Average risk</p>
              <p className="mt-1 font-mono text-2xl font-black text-slate-200">{averageRisk}<span className="text-xs text-slate-600">/100</span></p>
            </div>
          </div>

          <div className="mt-5 overflow-hidden rounded-full bg-slate-950 p-1">
            <div className="flex h-3 gap-1 overflow-hidden rounded-full">
              {filters.slice(1).map((level) => {
                const width = Math.max(3, (metrics[level] / total) * 100)
                return <div key={level} className={`${levelBar[level]} rounded-full`} style={{ width: `${width}%` }} />
              })}
            </div>
          </div>

          <div className="mt-5 grid gap-3 md:grid-cols-4">
            {[
              { level: 'LOW', range: '0–30', action: 'ALLOW', icon: ShieldCheck },
              { level: 'MEDIUM', range: '31–69', action: 'OTP / PASSWORD', icon: Fingerprint },
              { level: 'HIGH', range: '70–94', action: 'FREEZE SESSION', icon: Eye },
              { level: 'CRITICAL', range: '95–100', action: 'BLOCK ACCESS', icon: Activity },
            ].map(({ level, range, action, icon: Icon }) => (
              <div key={level} className="rounded-xl border border-slate-800 bg-slate-950/65 p-3">
                <div className="flex items-center justify-between">
                  <Icon className={`h-4 w-4 ${levelText[level]}`} />
                  <span className="font-mono text-[9px] text-slate-600">{range}</span>
                </div>
                <p className={`mt-3 text-[10px] font-black tracking-[0.12em] ${levelText[level]}`}>{level}</p>
                <p className="mt-1 text-[10px] font-semibold text-slate-500">{action}</p>
              </div>
            ))}
          </div>
        </div>

        <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-[10px] font-black uppercase tracking-[0.17em] text-slate-500">Priority activity</p>
              <h3 className="mt-1 text-lg font-semibold text-slate-100">Highest risk now</h3>
            </div>
            <span className="rounded-full border border-slate-800 bg-slate-950 px-2.5 py-1 font-mono text-[9px] text-slate-500">TOP 5</span>
          </div>
          <div className="mt-4 space-y-2">
            {topActivity.map((incident) => (
              <button
                key={incident.user_id}
                type="button"
                onClick={() => onInvestigate?.(incident)}
                className="group flex w-full items-center gap-3 rounded-xl border border-slate-800 bg-slate-950/60 p-3 text-left transition hover:border-slate-700 hover:bg-slate-950"
              >
                <div className={`grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-slate-800 bg-slate-900 font-mono text-xs font-black ${levelText[incident.level] || 'text-slate-300'}`}>
                  {incident.risk_score}
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <p className="truncate text-xs font-semibold text-slate-200">{incident.name}</p>
                    <span className="font-mono text-[9px] text-slate-600">{incident.user_id}</span>
                  </div>
                  <p className="mt-1 truncate text-[10px] text-slate-500">{incident.primary_reason}</p>
                </div>
                <ArrowRight className="h-4 w-4 shrink-0 text-slate-700 transition group-hover:translate-x-0.5 group-hover:text-slate-400" />
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/70">
        <div className="flex flex-col gap-4 border-b border-slate-800 p-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <div className="flex items-center gap-2 text-cyan-300">
              <Activity className="h-4 w-4" />
              <p className="text-[10px] font-black uppercase tracking-[0.17em]">Live incident queue</p>
            </div>
            <h3 className="mt-1 text-lg font-semibold text-slate-100">Access anomaly decisions</h3>
          </div>

          <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
            <div className="soc-scrollbar flex max-w-full items-center gap-1 overflow-x-auto rounded-xl border border-slate-800 bg-slate-950 p-1">
              <SlidersHorizontal className="mx-2 h-3.5 w-3.5 shrink-0 text-slate-600" />
              {filters.map((item) => (
                <button
                  key={item}
                  type="button"
                  onClick={() => setFilter(item)}
                  className={`shrink-0 rounded-lg px-2.5 py-1.5 text-[10px] font-black tracking-[0.08em] transition ${
                    filter === item
                      ? 'bg-slate-800 text-slate-100 shadow-sm'
                      : 'text-slate-600 hover:text-slate-200'
                  }`}
                >
                  {item}
                </button>
              ))}
            </div>

            <label className="flex min-w-[240px] items-center rounded-xl border border-slate-800 bg-slate-950 px-3 transition focus-within:border-cyan-500/30">
              <Search className="h-4 w-4 text-slate-600" />
              <input
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Search user ID or name…"
                className="w-full bg-transparent px-2 py-2.5 text-xs text-slate-200 outline-none placeholder:text-slate-700"
              />
            </label>
          </div>
        </div>

        <div className="soc-scrollbar overflow-x-auto">
          <table className="w-full min-w-[1320px] text-left text-sm">
            <thead className="bg-slate-950/80 text-[9px] uppercase tracking-[0.15em] text-slate-600">
              <tr>
                <th className="px-4 py-3.5">Identity</th>
                <th className="px-4 py-3.5">Department</th>
                <th className="px-4 py-3.5">Risk score</th>
                <th className="px-4 py-3.5">Level</th>
                <th className="px-4 py-3.5">Location</th>
                <th className="px-4 py-3.5">Primary reason</th>
                <th className="px-4 py-3.5">Status</th>
                <th className="px-4 py-3.5">Last seen</th>
                <th className="px-4 py-3.5">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {filteredIncidents.map((incident) => (
                <tr key={`${incident.user_id}-${incident.level}`} className="group transition hover:bg-slate-800/25">
                  <td className="px-4 py-3.5">
                    <p className="text-xs font-semibold text-slate-200">{incident.name}</p>
                    <p className="mt-1 font-mono text-[10px] font-bold text-cyan-400/80">{incident.user_id}</p>
                  </td>
                  <td className="px-4 py-3.5 text-xs text-slate-500">{incident.department}</td>
                  <td className="px-4 py-3.5">
                    <div className="flex items-center gap-3">
                      <span className={`w-7 font-mono text-xs font-black ${levelText[incident.level] || 'text-slate-200'}`}>{incident.risk_score}</span>
                      <div className="h-1.5 w-20 overflow-hidden rounded-full bg-slate-800">
                        <div
                          className={`h-full rounded-full ${levelBar[incident.level] || 'bg-slate-500'}`}
                          style={{ width: `${Math.min(100, Math.max(0, incident.risk_score))}%` }}
                        />
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3.5"><RiskBadge level={incident.level} /></td>
                  <td className="px-4 py-3.5 text-xs text-slate-500">{incident.location}</td>
                  <td className="max-w-[300px] px-4 py-3.5 text-xs leading-5 text-slate-400">{incident.primary_reason}</td>
                  <td className="px-4 py-3.5"><StatusBadge status={incident.status} /></td>
                  <td className="px-4 py-3.5">
                    <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-[10px] text-slate-600">
                      <Clock3 className="h-3 w-3" /> {incident.last_seen || 'just now'}
                    </span>
                  </td>
                  <td className="px-4 py-3.5">
                    <button
                      type="button"
                      onClick={() => onInvestigate?.(incident)}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-[10px] font-bold uppercase tracking-[0.08em] text-slate-300 transition hover:border-cyan-500/30 hover:bg-cyan-500/5 hover:text-cyan-200"
                    >
                      Investigate <ArrowRight className="h-3 w-3" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {filteredIncidents.length === 0 && (
            <div className="p-12 text-center">
              <Search className="mx-auto h-6 w-6 text-slate-700" />
              <p className="mt-3 text-sm font-semibold text-slate-400">No incidents found</p>
              <p className="mt-1 text-xs text-slate-600">Change the risk filter or search query.</p>
            </div>
          )}
        </div>
      </div>
    </section>
  )
}
