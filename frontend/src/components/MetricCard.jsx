import { motion } from 'framer-motion'
import { ArrowUpRight, CheckCircle2, KeyRound, LockKeyhole, ShieldX, TrendingUp } from 'lucide-react'

const variants = {
  low: {
    border: 'border-emerald-500/20',
    text: 'text-emerald-300',
    iconBg: 'bg-emerald-500/10 border-emerald-500/20',
    bar: 'bg-gradient-to-r from-emerald-500 to-emerald-400',
    glow: 'hover:shadow-glow-green',
    accentBg: 'bg-emerald-500/[0.04]',
    Icon: CheckCircle2,
  },
  medium: {
    border: 'border-amber-500/20',
    text: 'text-amber-300',
    iconBg: 'bg-amber-500/10 border-amber-500/20',
    bar: 'bg-gradient-to-r from-amber-500 to-amber-400',
    glow: 'hover:shadow-glow-amber',
    accentBg: 'bg-amber-500/[0.04]',
    Icon: KeyRound,
  },
  high: {
    border: 'border-orange-500/20',
    text: 'text-orange-300',
    iconBg: 'bg-orange-500/10 border-orange-500/20',
    bar: 'bg-gradient-to-r from-orange-600 to-orange-400',
    glow: 'hover:shadow-glow-orange',
    accentBg: 'bg-orange-500/[0.04]',
    Icon: LockKeyhole,
  },
  critical: {
    border: 'border-rose-500/20',
    text: 'text-rose-300',
    iconBg: 'bg-rose-500/10 border-rose-500/20',
    bar: 'bg-gradient-to-r from-rose-600 to-rose-400',
    glow: 'hover:shadow-glow-rose',
    accentBg: 'bg-rose-500/[0.04]',
    Icon: ShieldX,
  },
}

export default function MetricCard({ label, value, tone = 'low', subtitle, total = 1, index = 0 }) {
  const style = variants[tone] ?? variants.low
  const Icon = style.Icon
  const percentage = Math.round((Number(value || 0) / Math.max(1, Number(total || 1))) * 100)

  return (
    <motion.article
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay: index * 0.1, ease: [0.16, 1, 0.3, 1] }}
      className={`
        group relative overflow-hidden rounded-2xl border
        ${style.border} glass p-5
        transition-all duration-500 card-lift
        ${style.glow}
      `}
    >
      {/* Top shine line */}
      <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-white/[0.08] to-transparent" />

      {/* Ambient glow */}
      <div className={`absolute -right-8 -top-8 h-24 w-24 rounded-full ${style.accentBg} blur-2xl transition-opacity duration-500 opacity-0 group-hover:opacity-100`} />

      {/* Scan line effect */}
      <div className="absolute inset-0 overflow-hidden rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-700">
        <div className="absolute inset-x-0 h-[30%] bg-gradient-to-b from-transparent via-white/[0.015] to-transparent animate-scan" />
      </div>

      <div className="relative flex items-start justify-between gap-4">
        <div className="min-w-0">
          <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-slate-500">{label}</p>
          <div className="mt-3 flex items-end gap-2.5">
            <p className={`font-mono text-4xl font-black leading-none ${style.text}`}>{value}</p>
            <span className="pb-1 text-sm font-semibold text-slate-600">{percentage}%</span>
          </div>
          <p className="mt-2.5 text-[11px] font-medium text-slate-500">{subtitle}</p>
        </div>

        <div className={`
          rounded-xl border p-3 transition-all duration-300
          ${style.iconBg} ${style.text}
          group-hover:scale-110
        `}>
          <Icon className="h-5 w-5" />
        </div>
      </div>

      {/* Progress bar */}
      <div className="mt-5 h-1.5 overflow-hidden rounded-full bg-slate-800/80">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${Math.min(100, percentage)}%` }}
          transition={{ duration: 1.2, delay: 0.3 + index * 0.1, ease: [0.16, 1, 0.3, 1] }}
          className={`h-full rounded-full ${style.bar}`}
        />
      </div>

      <div className="mt-3 flex items-center justify-between text-[10px] uppercase tracking-[0.12em] text-slate-600">
        <span className="flex items-center gap-1.5">
          <TrendingUp className="h-3 w-3" />
          Policy engine
        </span>
        <span className={`inline-flex items-center gap-1 font-semibold ${style.text} transition-transform duration-300 group-hover:translate-x-0.5`}>
          Active <ArrowUpRight className="h-3 w-3" />
        </span>
      </div>
    </motion.article>
  )
}
