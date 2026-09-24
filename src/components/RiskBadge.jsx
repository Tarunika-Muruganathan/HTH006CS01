const levelStyles = {
  LOW: 'border-emerald-500/25 bg-emerald-500/10 text-emerald-300',
  MEDIUM: 'border-amber-500/25 bg-amber-500/10 text-amber-300',
  HIGH: 'border-orange-500/25 bg-orange-500/10 text-orange-300',
  CRITICAL: 'border-rose-500/25 bg-rose-500/10 text-rose-300',
}

const dots = {
  LOW: 'bg-emerald-400',
  MEDIUM: 'bg-amber-400',
  HIGH: 'bg-orange-500',
  CRITICAL: 'bg-rose-500',
}

export default function RiskBadge({ level = 'LOW' }) {
  const normalized = String(level).toUpperCase()
  const style = levelStyles[normalized] ?? levelStyles.LOW

  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[10px] font-bold tracking-[0.12em] ${style}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${dots[normalized] ?? dots.LOW}`} />
      {normalized}
    </span>
  )
}
