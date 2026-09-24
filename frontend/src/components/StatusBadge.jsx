import { motion } from 'framer-motion'

const styles = {
  APPROVED: {
    bg: 'bg-emerald-500/10',
    border: 'border-emerald-500/25',
    text: 'text-emerald-300',
    dot: 'bg-emerald-400',
    icon: '✓',
  },
  VERIFYING: {
    bg: 'bg-amber-500/10',
    border: 'border-amber-500/25',
    text: 'text-amber-300',
    dot: 'bg-amber-400',
    icon: '⟳',
  },
  FROZEN: {
    bg: 'bg-orange-500/10',
    border: 'border-orange-500/25',
    text: 'text-orange-300',
    dot: 'bg-orange-500',
    icon: '⏸',
  },
  BLOCKED: {
    bg: 'bg-rose-500/10',
    border: 'border-rose-500/25',
    text: 'text-rose-300',
    dot: 'bg-rose-500',
    icon: '✕',
  },
}

export default function StatusBadge({ status = 'APPROVED', size = 'sm' }) {
  const normalized = String(status).toUpperCase()
  const style = styles[normalized] ?? {
    bg: 'bg-slate-800/50',
    border: 'border-slate-700',
    text: 'text-slate-300',
    dot: 'bg-slate-500',
    icon: '?',
  }

  const isSmall = size === 'sm'

  return (
    <span
      className={`
        inline-flex items-center gap-2 rounded-full border
        font-mono font-bold tracking-[0.08em] uppercase
        transition-all duration-300
        ${style.bg} ${style.border} ${style.text}
        ${isSmall ? 'px-2.5 py-1 text-[10px]' : 'px-3.5 py-1.5 text-xs'}
      `}
    >
      <span className="relative flex h-2 w-2">
        {normalized === 'VERIFYING' && (
          <span className={`absolute inset-0 rounded-full ${style.dot} animate-pulse opacity-60`} />
        )}
        <span className={`relative inline-flex h-2 w-2 rounded-full ${style.dot}`} />
      </span>
      {normalized}
    </span>
  )
}
