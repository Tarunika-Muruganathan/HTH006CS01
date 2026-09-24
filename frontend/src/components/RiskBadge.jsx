import { motion, AnimatePresence } from 'framer-motion'

const levelStyles = {
  LOW: {
    bg: 'bg-emerald-500/10',
    border: 'border-emerald-500/25',
    text: 'text-emerald-300',
    dot: 'bg-emerald-400',
    glow: 'shadow-[0_0_12px_rgba(52,211,153,0.2)]',
  },
  MEDIUM: {
    bg: 'bg-amber-500/10',
    border: 'border-amber-500/25',
    text: 'text-amber-300',
    dot: 'bg-amber-400',
    glow: 'shadow-[0_0_12px_rgba(251,191,36,0.2)]',
  },
  HIGH: {
    bg: 'bg-orange-500/10',
    border: 'border-orange-500/25',
    text: 'text-orange-300',
    dot: 'bg-orange-500',
    glow: 'shadow-[0_0_12px_rgba(249,115,22,0.2)]',
  },
  CRITICAL: {
    bg: 'bg-rose-500/10',
    border: 'border-rose-500/25',
    text: 'text-rose-300',
    dot: 'bg-rose-500',
    glow: 'shadow-[0_0_12px_rgba(244,63,94,0.25)]',
  },
}

export default function RiskBadge({ level = 'LOW', animated = false }) {
  const normalized = String(level).toUpperCase()
  const style = levelStyles[normalized] ?? levelStyles.LOW

  const badge = (
    <span
      className={`
        inline-flex items-center gap-2 rounded-full border px-3 py-1.5
        text-[10px] font-bold tracking-[0.14em] uppercase
        transition-all duration-300
        ${style.bg} ${style.border} ${style.text}
        hover:${style.glow}
      `}
    >
      <span className="relative flex h-2 w-2">
        {normalized === 'CRITICAL' && (
          <span className={`absolute inset-0 rounded-full ${style.dot} animate-ping opacity-50`} />
        )}
        <span className={`relative inline-flex h-2 w-2 rounded-full ${style.dot}`} />
      </span>
      {normalized}
    </span>
  )

  if (animated) {
    return (
      <motion.div
        initial={{ scale: 0.8, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        transition={{ type: 'spring', stiffness: 400, damping: 20 }}
      >
        {badge}
      </motion.div>
    )
  }

  return badge
}
