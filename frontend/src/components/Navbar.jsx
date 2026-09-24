import { motion, AnimatePresence } from 'framer-motion'
import {
  Activity,
  Gauge,
  Radio,
  Shield,
  ShieldCheck,
  Users,
} from 'lucide-react'
import { useState } from 'react'

const navItems = [
  { key: 'dashboard', label: 'Operations Dashboard', icon: Gauge },
  { key: 'users', label: 'Identity Directory', icon: Users },
]

export default function Navbar({ activeView, onNavigate }) {
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
                    VECTRGUARD
                  </h1>
                </div>
                <p className="mt-1 truncate text-[11px] font-semibold uppercase tracking-[0.15em] text-slate-500">
                  Insider-Threat Anomaly Detection Platform
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
                Engine live
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
