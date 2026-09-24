import { ShieldAlert, FileText, ArrowRight } from 'lucide-react'

export default function RejectionPanel({ incident }) {
  if (!incident) return null
  const score = Number(incident.risk_score ?? 0)
  const level = String(incident.level ?? 'LOW').toUpperCase()
  const reason = incident.primary_reason ?? 'No explanation recorded'
  return (
    <div className="rounded-2xl border border-slate-800/60 bg-gradient-to-br from-slate-950/80 to-[#0a0f1a] p-6 shadow-glass">
      <div className="flex items-center gap-2.5">
        <div className="grid h-8 w-8 place-items-center rounded-lg border border-rose-500/20 bg-rose-500/10">
          <ShieldAlert className="h-4 w-4 text-rose-300" />
        </div>
        <div>
          <p className="text-[10px] font-black uppercase tracking-[0.18em] text-rose-300">Scoring / Rejection</p>
          <h3 className="text-sm font-bold text-white">Why this identity was flagged</h3>
        </div>
      </div>

      <div className="mt-4 grid gap-3 sm:grid-cols-3">
        <div className="rounded-xl border border-slate-800/40 bg-slate-950/60 p-3">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Risk score</p>
          <p className="mt-1 font-mono text-2xl font-black text-white">{score}<span className="text-sm text-slate-500">/100</span></p>
        </div>
        <div className="rounded-xl border border-slate-800/40 bg-slate-950/60 p-3">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Level</p>
          <p className="mt-1 font-mono text-xl font-black text-amber-300">{level}</p>
        </div>
        <div className="rounded-xl border border-slate-800/40 bg-slate-950/60 p-3">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Status</p>
          <p className="mt-1 font-mono text-sm font-bold text-slate-200">{incident.status ?? '—'}</p>
        </div>
      </div>

      <div className="mt-4 rounded-xl border border-slate-800/40 bg-slate-950/40 p-4">
        <div className="flex items-center gap-2 text-[10px] font-black uppercase tracking-[0.14em] text-slate-400">
          <FileText className="h-3.5 w-3.5" /> Explanation
        </div>
        <p className="mt-2 text-sm leading-relaxed text-slate-300">{reason}</p>
      </div>

      <div className="mt-3 text-[11px] text-slate-500">Score derived from behavioral baselining and anomaly deviation from the learned user profile.</div>
    </div>
  )
}
