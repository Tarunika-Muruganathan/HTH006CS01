import { useMemo, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Building2,
  ChevronRight,
  MapPin,
  Search,
  Shield,
  ShieldCheck,
  UserRoundCheck,
  UsersRound,
} from 'lucide-react'
import RiskBadge from '../components/RiskBadge'
import StatusBadge from '../components/StatusBadge'

const levelBar = {
  LOW: 'bg-gradient-to-r from-emerald-500 to-emerald-400',
  MEDIUM: 'bg-gradient-to-r from-amber-500 to-amber-400',
  HIGH: 'bg-gradient-to-r from-orange-600 to-orange-400',
  CRITICAL: 'bg-gradient-to-r from-rose-600 to-rose-400',
}

const levelBorderTop = {
  LOW: 'from-emerald-500/50 to-emerald-500/0',
  MEDIUM: 'from-amber-500/50 to-amber-500/0',
  HIGH: 'from-orange-500/50 to-orange-500/0',
  CRITICAL: 'from-rose-500/50 to-rose-500/0',
}

const levelGlow = {
  LOW: 'hover:shadow-[0_0_24px_rgba(52,211,153,0.08)]',
  MEDIUM: 'hover:shadow-[0_0_24px_rgba(251,191,36,0.08)]',
  HIGH: 'hover:shadow-[0_0_24px_rgba(249,115,22,0.08)]',
  CRITICAL: 'hover:shadow-[0_0_24px_rgba(244,63,94,0.1)]',
}

const statCards = (users) => {
  const elevated = users.filter((u) => Number(u.risk_score || 0) >= 70).length
  const verifying = users.filter((u) => u.status === 'VERIFYING').length
  return [
    {
      icon: UsersRound,
      value: users.length,
      label: 'Total monitored',
      color: 'text-cyan-300',
      border: 'border-cyan-500/20',
      bg: 'bg-cyan-500/10',
    },
    {
      icon: Shield,
      value: elevated,
      label: 'High / critical risk',
      color: 'text-orange-300',
      border: 'border-orange-500/20',
      bg: 'bg-orange-500/10',
    },
    {
      icon: UserRoundCheck,
      value: verifying,
      label: 'Awaiting verification',
      color: 'text-amber-300',
      border: 'border-amber-500/20',
      bg: 'bg-amber-500/10',
    },
  ]
}

export default function UsersView({ users }) {
  const [search, setSearch] = useState('')

  const filteredUsers = useMemo(() => {
    const query = search.trim().toLowerCase()
    if (!query) return users
    return users.filter((user) =>
      [user.user_id, user.name, user.department, user.location]
        .some((value) => String(value || '').toLowerCase().includes(query)),
    )
  }, [search, users])

  const stats = statCards(users)

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
            <UserRoundCheck className="h-4 w-4" />
            <p className="text-[10px] font-black uppercase tracking-[0.2em]">Identity intelligence</p>
          </div>
          <h2 className="mt-2 text-2xl font-bold tracking-tight text-white sm:text-3xl">
            Monitored Identity Directory
          </h2>
          <p className="mt-1.5 text-sm leading-relaxed text-slate-500">
            Behavioral baseline, risk posture, and enforcement state for all monitored identities.
          </p>
        </div>

        <label className="flex min-w-[300px] items-center rounded-xl border border-slate-800/60 bg-slate-900/50 px-4 shadow-depth transition-all duration-300 focus-within:border-cyan-500/30 focus-within:shadow-glow-cyan">
          <Search className="h-4 w-4 text-slate-600" />
          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search ID, name, team, location…"
            className="w-full bg-transparent px-2.5 py-3 text-xs text-slate-200 outline-none placeholder:text-slate-700"
          />
        </label>
      </motion.div>

      {/* ─── Stats Row ─── */}
      <div className="grid gap-3 sm:grid-cols-3">
        {stats.map((stat, i) => (
          <motion.div
            key={stat.label}
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 + i * 0.1 }}
            className={`relative overflow-hidden rounded-xl border ${stat.border} glass p-5 shadow-depth`}
          >
            <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-white/[0.06] to-transparent" />
            <div className={`grid h-9 w-9 place-items-center rounded-lg border ${stat.border} ${stat.bg}`}>
              <stat.icon className={`h-4 w-4 ${stat.color}`} />
            </div>
            <motion.p
              initial={{ opacity: 0, scale: 0.5 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: 0.4 + i * 0.1, type: 'spring', stiffness: 300 }}
              className={`mt-3 font-mono text-3xl font-black ${stat.color}`}
            >
              {stat.value}
            </motion.p>
            <p className="mt-1.5 text-[10px] font-bold uppercase tracking-[0.14em] text-slate-600">{stat.label}</p>
          </motion.div>
        ))}
      </div>

      {/* ─── User Cards Grid ─── */}
      <div className="grid gap-3.5 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4">
        <AnimatePresence>
          {filteredUsers.map((user, index) => (
            <motion.article
              key={user.user_id}
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95 }}
              transition={{ delay: Math.min(0.8, index * 0.03), duration: 0.4 }}
              className={`
                group relative overflow-hidden rounded-2xl border border-slate-800/50
                glass p-5 transition-all duration-400 card-lift
                hover:border-slate-700/60
                ${levelGlow[user.level] || ''}
              `}
            >
              {/* Top accent gradient */}
              <div className={`absolute inset-x-0 top-0 h-[2px] bg-gradient-to-r ${levelBorderTop[user.level] || 'from-slate-600/50 to-slate-600/0'}`} />

              {/* Hover shine */}
              <div className="absolute inset-0 overflow-hidden rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-700 pointer-events-none">
                <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/[0.015] to-transparent animate-shimmer" />
              </div>

              {/* Header */}
              <div className="relative flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <p className="font-mono text-[10px] font-black tracking-[0.1em] text-cyan-400/70">{user.user_id}</p>
                  <h3 className="mt-1.5 truncate text-sm font-bold text-white">{user.name}</h3>
                </div>
                <RiskBadge level={user.level} />
              </div>

              {/* Details */}
              <div className="mt-4 space-y-2.5 text-[11px] text-slate-500">
                <div className="flex items-center gap-2.5">
                  <div className="grid h-6 w-6 place-items-center rounded-md border border-slate-800/50 bg-slate-900/50">
                    <Building2 className="h-3 w-3 text-slate-600" />
                  </div>
                  {user.department}
                </div>
                <div className="flex items-center gap-2.5">
                  <div className="grid h-6 w-6 place-items-center rounded-md border border-slate-800/50 bg-slate-900/50">
                    <MapPin className="h-3 w-3 text-slate-600" />
                  </div>
                  {user.location}
                </div>
              </div>

              {/* Risk score panel */}
              <div className="mt-4 rounded-xl border border-slate-800/50 bg-slate-950/40 p-3.5">
                <div className="flex items-end justify-between gap-3">
                  <div>
                    <p className="text-[9px] font-bold uppercase tracking-[0.14em] text-slate-600">Risk score</p>
                    <p className="mt-1 font-mono text-2xl font-black text-white">
                      {user.risk_score}
                      <span className="text-[10px] text-slate-600">/100</span>
                    </p>
                  </div>
                  <StatusBadge status={user.status} />
                </div>
                <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-slate-800/60">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${Math.min(100, Math.max(0, user.risk_score))}%` }}
                    transition={{ duration: 0.8, delay: 0.3 + index * 0.02 }}
                    className={`h-full rounded-full ${levelBar[user.level] || 'bg-slate-600'}`}
                  />
                </div>
              </div>

              {/* Reason */}
              <p className="mt-3 line-clamp-2 min-h-8 text-[10px] leading-4 text-slate-600">
                {user.primary_reason}
              </p>
            </motion.article>
          ))}
        </AnimatePresence>
      </div>

      {/* Empty state */}
      {filteredUsers.length === 0 && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="rounded-2xl border border-dashed border-slate-800/60 p-16 text-center"
        >
          <div className="mx-auto grid h-12 w-12 place-items-center rounded-xl border border-slate-800/60 bg-slate-900/40">
            <Search className="h-5 w-5 text-slate-700" />
          </div>
          <p className="mt-4 text-sm font-semibold text-slate-400">
            No monitored identity matches "{search}".
          </p>
          <p className="mt-1 text-xs text-slate-600">Try a different search term.</p>
        </motion.div>
      )}
    </section>
  )
}
