import { motion } from 'framer-motion'

export default function RiskGauge({ value = 0, size = 120, label = 'Risk Score' }) {
  const radius = (size - 12) / 2
  const circumference = 2 * Math.PI * radius
  const progress = (Math.min(100, Math.max(0, value)) / 100) * circumference

  const getColor = (score) => {
    if (score >= 95) return { stroke: '#ef4444', glow: 'rgba(239, 68, 68, 0.3)', label: 'CRITICAL' }
    if (score >= 70) return { stroke: '#f97316', glow: 'rgba(249, 115, 22, 0.3)', label: 'HIGH' }
    if (score >= 30) return { stroke: '#fbbf24', glow: 'rgba(251, 191, 36, 0.3)', label: 'MEDIUM' }
    return { stroke: '#34d399', glow: 'rgba(52, 211, 153, 0.3)', label: 'LOW' }
  }

  const color = getColor(value)

  return (
    <div className="relative inline-flex flex-col items-center">
      <div className="relative" style={{ width: size, height: size }}>
        <svg
          viewBox={`0 0 ${size} ${size}`}
          className="absolute inset-0 -rotate-90"
        >
          {/* Track */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke="rgba(51, 65, 85, 0.3)"
            strokeWidth="6"
            strokeLinecap="round"
          />
          {/* Progress */}
          <motion.circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={color.stroke}
            strokeWidth="6"
            strokeLinecap="round"
            strokeDasharray={circumference}
            initial={{ strokeDashoffset: circumference }}
            animate={{ strokeDashoffset: circumference - progress }}
            transition={{ duration: 1.5, delay: 0.5, ease: [0.16, 1, 0.3, 1] }}
            style={{ filter: `drop-shadow(0 0 8px ${color.glow})` }}
          />
        </svg>

        {/* Center content */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <motion.span
            initial={{ opacity: 0, scale: 0.5 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.8, type: 'spring', stiffness: 300 }}
            className="font-mono text-3xl font-black text-white"
          >
            {value}
          </motion.span>
          <span className="text-[8px] font-bold uppercase tracking-[0.2em] text-slate-600">
            /100
          </span>
        </div>
      </div>

      <div className="mt-2 flex flex-col items-center">
        <span className="text-[9px] font-bold uppercase tracking-[0.15em] text-slate-600">{label}</span>
        <span
          className="mt-1 text-[10px] font-black uppercase tracking-[0.12em]"
          style={{ color: color.stroke }}
        >
          {color.label}
        </span>
      </div>
    </div>
  )
}
