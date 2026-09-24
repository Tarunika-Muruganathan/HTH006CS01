import { motion, AnimatePresence } from 'framer-motion'
import {
  Activity,
  ChevronDown,
  Gauge,
  Menu,
  Radio,
  Shield,
  ShieldCheck,
  Users,
  X,
  Zap,
} from 'lucide-react'
import { useState } from 'react'

const simulationButtons = [
  {
    type: 'normal',
    label: 'Normal',
    id: 'EMP101',
    color: 'emerald',
    active: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300 hover:bg-emerald-500/15',
    dot: 'bg-emerald-400',
    glow: 'hover:shadow-[0_0_20px_rgba(52,211,153,0.15)]',
  },
  {
    type: 'medium',
    label: 'Medium',
    id: 'EMP205',
    color: 'amber',
    active: 'border-amber-500/30 bg-amber-500/10 text-amber-300 hover:bg-amber-500/15',
    dot: 'bg-amber-400',
    glow: 'hover:shadow-[0_0_20px_rgba(251,191,36,0.15)]',
  },
  {
    type: 'high',
    label: 'High',
    id: 'EMP302',
    color: 'orange',
    active: 'border-orange-500/30 bg-orange-500/10 text-orange-300 hover:bg-orange-500/15',
    dot: 'bg-orange-500',
    glow: 'hover:shadow-[0_0_20px_rgba(249,115,22,0.15)]',
  },
  {
    type: 'critical',
    label: 'Critical',
    id: 'EMP928',
    color: 'rose',
    active: 'border-rose-500/30 bg-rose-500/10 text-rose-300 hover:bg-rose-500/15',
    dot: 'bg-rose-500',
    glow: 'hover:shadow-[0_0_20px_rgba(244,63,94,0.15)]',
  },
]

const navItems = [
  { key: 'dashboard', label: 'Operations Dashboard', icon: Gauge },
  { key: 'users', label: 'Identity Directory', icon: Users },
]

export default function Navbar({ activeView, onNavigate, onSimulation, simulatingType }) {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)

  return (
    <header className="sticky top-0 z-30 border-b border-slate-800/60 glass-heavy">
      {/* Top animated gradient line */}
      <div className="absolute inset-x-0 top-0 h-[1px]">
        <div className="h-full w-full bg-gradient-to-r from-transparent via-cyan-500/40 to-transparent" />
      </div>

      <div className="mx-auto max-w-[1720px] px-4 py-4 lg:px-6">
        <div className="flex flex-col gap-5 2xl:flex-row 2xl:items-center 2xl:justify-between">
          {/* ─── Brand + Status ─── */}
          <div className="min-w-0">
            <div className="flex items-center gap-4">
              {/* Logo */}
              <div className="relative">
                <div className="grid h-11 w-11 shrink-0 place-items-center rounded-xl border border-emerald-500/25 bg-emerald-500/10 text-emerald-300 shadow-glow-green transition-all duration-300 hover:scale-105">
                  <Shield className="h-5.5 w-5.5" />
                </div>
                <span className="absolute -right-0.5 -top-0.5 flex h-3 w-3">
                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-40" />
                  <span className="relative inline-flex h-3 w-3 rounded-full border-2 border-gray-950 bg-emerald-400" />
                </span>
              </div>

              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2.5">
                  <h1 className="truncate font-mono text-base font-black tracking-[0.1em] text-white sm:text-lg">
                    CYBERSHIELD
                  </h1>
                  <span className="rounded-md border border-slate-700/60 bg-slate-800/60 px-2 py-0.5 font-mono text-[9px] font-bold tracking-[0.14em] text-slate-500">
                    HTH-CS-07
                  </span>
                </div>
                <p className="mt-1 truncate text-[11px] font-semibold uppercase tracking-[0.15em] text-slate-500">
                  Explainable Insider-Threat Anomaly Detector
                </p>
              </div>
            </div>

            {/* Status indicators */}
            <div className="mt-3.5 flex flex-wrap items-center gap-x-5 gap-y-2 pl-0 text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-500 sm:pl-[60px]">
              <span className="inline-flex items-center gap-2 text-emerald-300/90">
                <span className="relative flex h-2 w-2">
                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-50" />
                  <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-400" />
                </span>
                Engine live · 35 identities
              </span>
              <span className="inline-flex items-center gap-1.5 text-slate-500">
                <Activity className="h-3.5 w-3.5 text-cyan-400/60" />
                Behavioral analytics
              </span>
              <span className="inline-flex items-center gap-1.5 text-slate-500">
                <Radio className="h-3.5 w-3.5 text-violet-400/60" />
                Event stream
              </span>
            </div>
          </div>

          {/* ─── Attack Injector Panel ─── */}
          <div className="rounded-xl border border-slate-800/60 bg-slate-900/50 p-2.5 shadow-depth">
            <div className="mb-2.5 flex items-center justify-between px-1.5">
              <span className="flex items-center gap-2 text-[9px] font-bold uppercase tracking-[0.16em] text-slate-500">
                <Zap className="h-3 w-3 text-amber-400/70" />
                Demo attack injector
              </span>
              <span className="rounded-full border border-slate-700/50 bg-slate-800/50 px-2 py-0.5 font-mono text-[8px] font-bold tracking-wider text-slate-600">
                ONE-CLICK
              </span>
            </div>
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              {simulationButtons.map((button) => (
                <motion.button
                  key={button.type}
                  type="button"
                  whileTap={{ scale: 0.97 }}
                  onClick={() => onSimulation(button.type)}
                  disabled={Boolean(simulatingType)}
                  className={`
                    group relative min-w-[120px] overflow-hidden rounded-lg border
                    bg-slate-950/60 px-3 py-2.5 text-left
                    transition-all duration-300
                    disabled:cursor-not-allowed disabled:opacity-40
                    ${button.active} ${button.glow}
                  `}
                >
                  {/* Shimmer on hover */}
                  <div className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-500 overflow-hidden">
                    <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/[0.03] to-transparent animate-shimmer" />
                  </div>

                  <span className="relative flex items-center justify-between gap-3">
                    <span className="flex items-center gap-2">
                      <span className={`h-2.5 w-2.5 rounded-full ${button.dot} transition-transform duration-300 group-hover:scale-125`} />
                      <span className="text-[10px] font-black uppercase tracking-[0.12em]">{button.label}</span>
                    </span>
                    <Zap className="h-3.5 w-3.5 opacity-40 transition-all duration-300 group-hover:opacity-100 group-hover:text-current" />
                  </span>
                  <span className="relative mt-1.5 block font-mono text-[10px] opacity-50">
                    {simulatingType === button.type ? (
                      <motion.span
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        className="text-current"
                      >
                        INJECTING…
                      </motion.span>
                    ) : (
                      button.id
                    )}
                  </span>
                </motion.button>
              ))}
            </div>
          </div>
        </div>

        {/* ─── Navigation ─── */}
        <nav className="mt-4 flex gap-1.5 border-t border-slate-800/40 pt-4">
          {navItems.map((item) => {
            const isActive = activeView === item.key
            const Icon = item.icon
            return (
              <button
                key={item.key}
                type="button"
                onClick={() => onNavigate(item.key)}
                className={`
                  relative inline-flex items-center gap-2 rounded-xl px-4 py-2.5
                  text-xs font-semibold transition-all duration-300
                  ${isActive
                    ? 'border border-slate-700/60 bg-slate-800/70 text-white shadow-depth'
                    : 'border border-transparent text-slate-500 hover:bg-slate-800/30 hover:text-slate-200'
                  }
                `}
              >
                <Icon className="h-4 w-4" />
                {item.label}
                {isActive && (
                  <motion.div
                    layoutId="nav-indicator"
                    className="absolute inset-x-2 -bottom-[17px] h-[2px] rounded-full bg-gradient-to-r from-cyan-400 via-cyan-300 to-emerald-400"
                    transition={{ type: 'spring', stiffness: 400, damping: 30 }}
                  />
                )}
              </button>
            )
          })}
        </nav>
      </div>
    </header>
  )
}
