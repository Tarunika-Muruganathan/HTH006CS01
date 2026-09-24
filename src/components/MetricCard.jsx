import { ArrowUpRight, CheckCircle2, KeyRound, LockKeyhole, ShieldX } from 'lucide-react'

const variants = {
  low: {
    border: 'border-emerald-500/25',
    text: 'text-emerald-300',
    iconBg: 'bg-emerald-500/10 border-emerald-500/20',
    glow: 'group-hover:shadow-soc-green',
    bar: 'bg-emerald-400',
    Icon: CheckCircle2,
  },
  medium: {
    border: 'border-amber-500/25',
    text: 'text-amber-300',
    iconBg: 'bg-amber-500/10 border-amber-500/20',
    glow: 'group-hover:shadow-soc-amber',
    bar: 'bg-amber-400',
    Icon: KeyRound,
  },
  high: {
    border: 'border-orange-500/25',
    text: 'text-orange-300',
    iconBg: 'bg-orange-500/10 border-orange-500/20',
    glow: 'group-hover:shadow-soc-orange',
    bar: 'bg-orange-500',
    Icon: LockKeyhole,
  },
  critical: {
    border: 'border-rose-500/25',
    text: 'text-rose-300',
    iconBg: 'bg-rose-500/10 border-rose-500/20',
    glow: 'group-hover:shadow-soc-rose',
    bar: 'bg-rose-500',
    Icon: ShieldX,
  },
}

export default function MetricCard({ label, value, tone = 'low', subtitle, total = 1 }) {
  const style = variants[tone] ?? variants.low
  const Icon = style.Icon
  const percentage = Math.round((Number(value || 0) / Math.max(1, Number(total || 1))) * 100)

  return (
    <article className={`group relative overflow-hidden rounded-2xl border ${style.border} bg-slate-900/75 p-5 transition duration-300 hover:-translate-y-0.5 ${style.glow}`}>
      <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-slate-600/40 to-transparent" />
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <p className="text-[10px] font-bold uppercase tracking-[0.16em] text-slate-500">{label}</p>
          <div className="mt-3 flex items-end gap-2">
            <p className={`font-mono text-4xl font-black leading-none ${style.text}`}>{value}</p>
            <span className="pb-1 text-[11px] font-semibold text-slate-600">{percentage}%</span>
          </div>
          <p className="mt-2 text-xs text-slate-500">{subtitle}</p>
        </div>
        <div className={`rounded-xl border p-2.5 ${style.iconBg} ${style.text}`}>
          <Icon className="h-5 w-5" />
        </div>
      </div>

      <div className="mt-5 h-1 overflow-hidden rounded-full bg-slate-800">
        <div className={`h-full rounded-full ${style.bar}`} style={{ width: `${Math.min(100, percentage)}%` }} />
      </div>

      <div className="mt-3 flex items-center justify-between text-[10px] uppercase tracking-[0.12em] text-slate-600">
        <span>Policy engine</span>
        <span className={`inline-flex items-center gap-1 font-semibold ${style.text}`}>
          Active <ArrowUpRight className="h-3 w-3" />
        </span>
      </div>
    </article>
  )
}
