const styles = {
  APPROVED: 'border-emerald-500/25 bg-emerald-500/10 text-emerald-300',
  VERIFYING: 'border-amber-500/25 bg-amber-500/10 text-amber-300',
  FROZEN: 'border-orange-500/25 bg-orange-500/10 text-orange-300',
  BLOCKED: 'border-rose-500/25 bg-rose-500/10 text-rose-300',
}

const dotStyles = {
  APPROVED: 'bg-emerald-400',
  VERIFYING: 'bg-amber-400',
  FROZEN: 'bg-orange-500',
  BLOCKED: 'bg-rose-500',
}

export default function StatusBadge({ status = 'APPROVED' }) {
  const normalized = String(status).toUpperCase()
  const style = styles[normalized] ?? 'border-slate-700 bg-slate-800 text-slate-300'
  const dot = dotStyles[normalized] ?? 'bg-slate-500'

  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 font-mono text-[10px] font-bold tracking-[0.08em] ${style}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${dot}`} />
      {normalized}
    </span>
  )
}
