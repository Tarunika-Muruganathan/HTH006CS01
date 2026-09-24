import {
  Activity,
  Gauge,
  Radio,
  ShieldCheck,
  Users,
  Zap,
} from 'lucide-react'

const simulationButtons = [
  { type: 'normal', label: 'Normal', id: 'EMP101', tone: 'emerald', active: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300' },
  { type: 'medium', label: 'Medium', id: 'EMP205', tone: 'amber', active: 'border-amber-500/40 bg-amber-500/10 text-amber-300' },
  { type: 'high', label: 'High', id: 'EMP302', tone: 'orange', active: 'border-orange-500/40 bg-orange-500/10 text-orange-300' },
  { type: 'critical', label: 'Critical', id: 'EMP928', tone: 'rose', active: 'border-rose-500/40 bg-rose-500/10 text-rose-300' },
]

const dotClass = {
  emerald: 'bg-emerald-400',
  amber: 'bg-amber-400',
  orange: 'bg-orange-500',
  rose: 'bg-rose-500',
}

export default function Navbar({ activeView, onNavigate, onSimulation, simulatingType }) {
  return (
    <header className="sticky top-0 z-30 border-b border-slate-800/90 bg-slate-950/90 backdrop-blur-xl">
      <div className="mx-auto max-w-[1680px] px-4 py-3 lg:px-6">
        <div className="flex flex-col gap-4 2xl:flex-row 2xl:items-center 2xl:justify-between">
          <div className="min-w-0">
            <div className="flex items-center gap-3">
              <div className="relative grid h-10 w-10 shrink-0 place-items-center rounded-xl border border-emerald-500/30 bg-emerald-500/10 text-emerald-300 shadow-soc-green">
                <ShieldCheck className="h-5 w-5" />
                <span className="absolute -right-1 -top-1 h-2.5 w-2.5 rounded-full border-2 border-slate-950 bg-emerald-400" />
              </div>
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <h1 className="truncate font-mono text-sm font-black tracking-[0.08em] text-slate-100 sm:text-base">
                    CYBERSHIELD
                  </h1>
                  <span className="rounded-md border border-slate-700 bg-slate-900 px-2 py-0.5 font-mono text-[9px] font-bold tracking-[0.12em] text-slate-500">
                    HTH-CS-07
                  </span>
                </div>
                <p className="mt-1 truncate text-[11px] font-semibold uppercase tracking-[0.13em] text-slate-500">
                  Explainable Insider-Threat Anomaly Detector
                </p>
              </div>
            </div>

            <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-2 pl-0 text-[10px] font-semibold uppercase tracking-[0.1em] text-slate-500 sm:pl-[52px]">
              <span className="inline-flex items-center gap-2 text-emerald-300">
                <span className="relative flex h-2 w-2">
                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-60" />
                  <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-400" />
                </span>
                Engine live · 35 identities
              </span>
              <span className="inline-flex items-center gap-1.5">
                <Activity className="h-3.5 w-3.5" />
                Behavioral analytics active
              </span>
              <span className="inline-flex items-center gap-1.5">
                <Radio className="h-3.5 w-3.5" />
                Event stream online
              </span>
            </div>
          </div>

          <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-2">
            <div className="mb-2 flex items-center justify-between px-1">
              <span className="text-[9px] font-bold uppercase tracking-[0.15em] text-slate-600">Demo attack injector</span>
              <span className="font-mono text-[9px] text-slate-700">ONE-CLICK</span>
            </div>
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              {simulationButtons.map((button) => (
                <button
                  key={button.type}
                  type="button"
                  onClick={() => onSimulation(button.type)}
                  disabled={Boolean(simulatingType)}
                  className={`group min-w-[118px] rounded-lg border border-slate-800 bg-slate-950/70 px-3 py-2 text-left transition hover:-translate-y-px disabled:cursor-not-allowed disabled:opacity-50 ${button.active}`}
                >
                  <span className="flex items-center justify-between gap-3">
                    <span className="flex items-center gap-2">
                      <span className={`h-2 w-2 rounded-full ${dotClass[button.tone]}`} />
                      <span className="text-[10px] font-bold uppercase tracking-[0.1em]">{button.label}</span>
                    </span>
                    <Zap className="h-3.5 w-3.5 opacity-50 transition group-hover:opacity-100" />
                  </span>
                  <span className="mt-1.5 block font-mono text-[10px] opacity-60">
                    {simulatingType === button.type ? 'INJECTING…' : button.id}
                  </span>
                </button>
              ))}
            </div>
          </div>
        </div>

        <nav className="mt-3 flex gap-1 border-t border-slate-900 pt-3">
          <button
            type="button"
            onClick={() => onNavigate('dashboard')}
            className={`inline-flex items-center gap-2 rounded-lg px-3 py-2 text-xs font-semibold transition ${
              activeView === 'dashboard'
                ? 'border border-slate-700 bg-slate-800 text-slate-100 shadow-sm'
                : 'border border-transparent text-slate-500 hover:bg-slate-900 hover:text-slate-200'
            }`}
          >
            <Gauge className="h-4 w-4" /> Operations Dashboard
          </button>
          <button
            type="button"
            onClick={() => onNavigate('users')}
            className={`inline-flex items-center gap-2 rounded-lg px-3 py-2 text-xs font-semibold transition ${
              activeView === 'users'
                ? 'border border-slate-700 bg-slate-800 text-slate-100 shadow-sm'
                : 'border border-transparent text-slate-500 hover:bg-slate-900 hover:text-slate-200'
            }`}
          >
            <Users className="h-4 w-4" /> Identity Directory
          </button>
        </nav>
      </div>
    </header>
  )
}
