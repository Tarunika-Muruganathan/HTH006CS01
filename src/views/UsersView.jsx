import { useMemo, useState } from 'react'
import { Building2, MapPin, Search, ShieldCheck, UserRoundCheck, UsersRound } from 'lucide-react'
import RiskBadge from '../components/RiskBadge'
import StatusBadge from '../components/StatusBadge'

const levelBar = {
  LOW: 'bg-emerald-400',
  MEDIUM: 'bg-amber-400',
  HIGH: 'bg-orange-500',
  CRITICAL: 'bg-rose-500',
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

  const elevated = users.filter((user) => Number(user.risk_score || 0) >= 70).length
  const verifying = users.filter((user) => user.status === 'VERIFYING').length

  return (
    <section className="space-y-5">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <div className="flex items-center gap-2 text-emerald-300">
            <UserRoundCheck className="h-4 w-4" />
            <p className="text-[10px] font-black uppercase tracking-[0.18em]">Identity intelligence</p>
          </div>
          <h2 className="mt-2 text-2xl font-bold tracking-tight text-slate-100 sm:text-3xl">Monitored Identity Directory</h2>
          <p className="mt-1 text-sm text-slate-500">Behavioral baseline, latest risk posture, location, and enforcement state for all 35 identities.</p>
        </div>

        <label className="flex min-w-[290px] items-center rounded-xl border border-slate-800 bg-slate-900/80 px-3 transition focus-within:border-cyan-500/30">
          <Search className="h-4 w-4 text-slate-600" />
          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search ID, name, team, location…"
            className="w-full bg-transparent px-2 py-3 text-xs text-slate-200 outline-none placeholder:text-slate-700"
          />
        </label>
      </div>

      <div className="grid gap-3 sm:grid-cols-3">
        <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
          <UsersRound className="h-4 w-4 text-cyan-300" />
          <p className="mt-3 font-mono text-2xl font-black text-slate-100">{users.length}</p>
          <p className="mt-1 text-[10px] font-bold uppercase tracking-[0.13em] text-slate-600">Total monitored</p>
        </div>
        <div className="rounded-xl border border-orange-500/20 bg-slate-900/70 p-4">
          <ShieldCheck className="h-4 w-4 text-orange-300" />
          <p className="mt-3 font-mono text-2xl font-black text-orange-300">{elevated}</p>
          <p className="mt-1 text-[10px] font-bold uppercase tracking-[0.13em] text-slate-600">High / critical risk</p>
        </div>
        <div className="rounded-xl border border-amber-500/20 bg-slate-900/70 p-4">
          <UserRoundCheck className="h-4 w-4 text-amber-300" />
          <p className="mt-3 font-mono text-2xl font-black text-amber-300">{verifying}</p>
          <p className="mt-1 text-[10px] font-bold uppercase tracking-[0.13em] text-slate-600">Awaiting verification</p>
        </div>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4">
        {filteredUsers.map((user) => (
          <article key={user.user_id} className="group relative overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/65 p-4 transition duration-300 hover:-translate-y-0.5 hover:border-slate-700 hover:bg-slate-900">
            <div className={`absolute inset-x-0 top-0 h-0.5 ${levelBar[user.level] || 'bg-slate-600'} opacity-70`} />
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <p className="font-mono text-[10px] font-black tracking-[0.08em] text-cyan-400/80">{user.user_id}</p>
                <h3 className="mt-1 truncate text-sm font-bold text-slate-200">{user.name}</h3>
              </div>
              <RiskBadge level={user.level} />
            </div>

            <div className="mt-4 space-y-2 text-[11px] text-slate-500">
              <div className="flex items-center gap-2"><Building2 className="h-3.5 w-3.5 text-slate-700" /> {user.department}</div>
              <div className="flex items-center gap-2"><MapPin className="h-3.5 w-3.5 text-slate-700" /> {user.location}</div>
            </div>

            <div className="mt-4 rounded-xl border border-slate-800 bg-slate-950/55 p-3">
              <div className="flex items-end justify-between gap-3">
                <div>
                  <p className="text-[9px] font-bold uppercase tracking-[0.13em] text-slate-600">Risk score</p>
                  <p className="mt-1 font-mono text-2xl font-black text-slate-200">{user.risk_score}<span className="text-[10px] text-slate-600">/100</span></p>
                </div>
                <StatusBadge status={user.status} />
              </div>
              <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-slate-800">
                <div className={`h-full rounded-full ${levelBar[user.level] || 'bg-slate-600'}`} style={{ width: `${Math.min(100, Math.max(0, user.risk_score))}%` }} />
              </div>
            </div>

            <p className="mt-3 line-clamp-2 min-h-8 text-[10px] leading-4 text-slate-600">{user.primary_reason}</p>
          </article>
        ))}
      </div>

      {filteredUsers.length === 0 && (
        <div className="rounded-2xl border border-dashed border-slate-800 p-12 text-center text-sm text-slate-500">
          No monitored identity matches “{search}”.
        </div>
      )}
    </section>
  )
}
