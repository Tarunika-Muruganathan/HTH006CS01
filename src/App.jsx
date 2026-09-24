import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  Clock3,
  Fingerprint,
  MapPin,
  RefreshCw,
  ShieldCheck,
  ShieldX,
  X,
} from 'lucide-react'
import api from './api'
import Navbar from './components/Navbar'
import RiskBadge from './components/RiskBadge'
import StatusBadge from './components/StatusBadge'
import VerificationModal from './components/VerificationModal'
import DashboardView from './views/DashboardView'
import UsersView from './views/UsersView'
import { demoIncidents, getSimulationFallback, monitoredUsers } from './data'

const normalizeIncident = (incident = {}) => ({
  user_id: incident.user_id ?? incident.userId ?? incident.employee_id ?? 'UNKNOWN',
  name: incident.name ?? incident.user_name ?? 'Unknown user',
  department: incident.department ?? incident.dept ?? 'Unknown',
  risk_score: Number(incident.risk_score ?? incident.score ?? 0),
  level: String(incident.level ?? incident.risk_level ?? 'LOW').toUpperCase(),
  location: incident.location ?? incident.source_location ?? 'Unknown',
  primary_reason: incident.primary_reason ?? incident.reason ?? incident.explanation ?? 'Anomaly detected',
  status: String(incident.status ?? 'APPROVED').toUpperCase(),
  last_seen: incident.last_seen ?? incident.timestamp ?? 'just now',
})

const upsertIncident = (items, incoming) => {
  const normalized = normalizeIncident(incoming)
  return [normalized, ...items.filter((item) => item.user_id !== normalized.user_id)]
}

const actionCopy = {
  APPROVED: 'Access allowed. Activity remains under passive monitoring.',
  VERIFYING: 'Access paused. Step-up OTP or password verification is required.',
  FROZEN: 'Current session frozen. Sensitive actions are temporarily denied.',
  BLOCKED: 'Access blocked immediately. Escalation to the SOC queue is recommended.',
}

const levelIcon = {
  LOW: ShieldCheck,
  MEDIUM: Fingerprint,
  HIGH: AlertTriangle,
  CRITICAL: ShieldX,
}

export default function App() {
  const [activeView, setActiveView] = useState('dashboard')
  const [incidents, setIncidents] = useState(demoIncidents)
  const [verificationIncident, setVerificationIncident] = useState(null)
  const [selectedIncident, setSelectedIncident] = useState(null)
  const [simulatingType, setSimulatingType] = useState('')
  const [backendOnline, setBackendOnline] = useState(null)
  const [lastSync, setLastSync] = useState(null)
  const [notice, setNotice] = useState(null)

  const showNotice = useCallback((message, tone = 'info') => {
    setNotice({ message, tone })
    window.setTimeout(() => setNotice(null), 3000)
  }, [])

  const pollAlerts = useCallback(async () => {
    try {
      const { data } = await api.get('/alerts')
      const payload = Array.isArray(data) ? data : data?.alerts ?? data?.incidents ?? data?.results ?? []
      if (Array.isArray(payload) && payload.length) setIncidents(payload.map(normalizeIncident))
      setBackendOnline(true)
      setLastSync(new Date())
    } catch {
      setBackendOnline(false)
    }
  }, [])

  useEffect(() => {
    pollAlerts()
    const timer = window.setInterval(pollAlerts, 5000)
    return () => window.clearInterval(timer)
  }, [pollAlerts])

  useEffect(() => {
    const verifying = incidents.find((incident) => incident.status === 'VERIFYING')
    if (verifying && verifying.user_id === 'EMP205') {
      setVerificationIncident((current) => current ?? verifying)
    }
  }, [incidents])

  const handleSimulation = async (type) => {
    setSimulatingType(type)
    try {
      const { data } = await api.post(`/simulation/inject/${type}`)
      const candidate = data?.incident ?? data?.alert ?? data
      const normalized = normalizeIncident(candidate)
      setIncidents((current) => upsertIncident(current, normalized))
      setBackendOnline(true)
      setLastSync(new Date())
      showNotice(`${normalized.user_id}: ${normalized.status} · risk ${normalized.risk_score}/100`, normalized.level)
      if (type === 'medium' || normalized.status === 'VERIFYING') setVerificationIncident(normalized)
    } catch {
      const fallback = getSimulationFallback(type)
      setIncidents((current) => upsertIncident(current, fallback))
      if (type === 'medium') setVerificationIncident(fallback)
      setBackendOnline(false)
      showNotice(`${fallback.user_id}: demo event injected · ${fallback.status}`, fallback.level)
    } finally {
      setSimulatingType('')
    }
  }

  const handleVerified = (verifiedIncident) => {
    setIncidents((current) =>
      current.map((incident) =>
        incident.user_id === verifiedIncident.user_id
          ? { ...incident, ...verifiedIncident, status: 'APPROVED' }
          : incident,
      ),
    )
    showNotice(`${verifiedIncident.user_id}: identity verified · access approved`, 'LOW')
  }

  const users = useMemo(() => monitoredUsers.map((user) => {
    const live = incidents.find((incident) => incident.user_id === user.user_id)
    return live ? { ...user, ...live } : user
  }), [incidents])

  const syncLabel = lastSync
    ? lastSync.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    : '—'

  const SelectedIcon = selectedIncident ? (levelIcon[selectedIncident.level] ?? Activity) : Activity

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <Navbar
        activeView={activeView}
        onNavigate={setActiveView}
        onSimulation={handleSimulation}
        simulatingType={simulatingType}
      />

      <main className="mx-auto max-w-[1680px] px-4 py-5 lg:px-6">
        <div className="mb-5 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-800/80 bg-slate-900/45 px-3.5 py-2.5 text-[10px] font-semibold uppercase tracking-[0.1em] text-slate-600">
          <div className="flex flex-wrap items-center gap-x-5 gap-y-2">
            <span className="inline-flex items-center gap-2">
              <span className={`h-2 w-2 rounded-full ${backendOnline ? 'bg-emerald-400' : backendOnline === false ? 'bg-amber-400' : 'bg-slate-600'}`} />
              API {backendOnline ? 'Connected' : backendOnline === false ? 'Demo fallback' : 'Checking'}
            </span>
            <span className="inline-flex items-center gap-1.5"><Activity className="h-3.5 w-3.5" /> Rule engine active</span>
            <span className="inline-flex items-center gap-1.5"><ShieldCheck className="h-3.5 w-3.5" /> Enforcement armed</span>
          </div>
          <div className="flex items-center gap-2 font-mono normal-case tracking-normal">
            <RefreshCw className="h-3 w-3" /> Poll 5s · last sync {syncLabel}
          </div>
        </div>

        {activeView === 'dashboard'
          ? <DashboardView incidents={incidents} onInvestigate={setSelectedIncident} />
          : <UsersView users={users} />}
      </main>

      <VerificationModal
        open={Boolean(verificationIncident)}
        incident={verificationIncident}
        onClose={() => setVerificationIncident(null)}
        onVerified={handleVerified}
      />

      {selectedIncident && (
        <div className="fixed inset-0 z-40 bg-slate-950/70 backdrop-blur-sm" onClick={() => setSelectedIncident(null)}>
          <aside
            className="soc-scrollbar absolute right-0 top-0 h-full w-full max-w-xl overflow-y-auto border-l border-slate-800 bg-slate-900 shadow-2xl shadow-black/60"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="sticky top-0 z-10 border-b border-slate-800 bg-slate-900/95 p-5 backdrop-blur-xl">
              <div className="flex items-start justify-between gap-4">
                <div className="flex gap-3">
                  <div className="grid h-10 w-10 shrink-0 place-items-center rounded-xl border border-slate-700 bg-slate-950 text-slate-300">
                    <SelectedIcon className="h-5 w-5" />
                  </div>
                  <div>
                    <p className="text-[10px] font-black uppercase tracking-[0.18em] text-cyan-300">Explainable investigation</p>
                    <h2 className="mt-1 text-xl font-bold text-slate-100">{selectedIncident.name}</h2>
                    <p className="mt-1 font-mono text-[10px] font-semibold text-slate-500">{selectedIncident.user_id} · {selectedIncident.department}</p>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => setSelectedIncident(null)}
                  className="rounded-lg border border-transparent p-1.5 text-slate-600 transition hover:border-slate-800 hover:bg-slate-950 hover:text-slate-300"
                  aria-label="Close investigation drawer"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>
            </div>

            <div className="space-y-4 p-5">
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
                  <p className="text-[9px] font-bold uppercase tracking-[0.13em] text-slate-600">Risk</p>
                  <p className="mt-1 font-mono text-2xl font-black text-slate-100">{selectedIncident.risk_score}</p>
                </div>
                <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
                  <p className="text-[9px] font-bold uppercase tracking-[0.13em] text-slate-600">Level</p>
                  <div className="mt-2"><RiskBadge level={selectedIncident.level} /></div>
                </div>
                <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
                  <p className="text-[9px] font-bold uppercase tracking-[0.13em] text-slate-600">Status</p>
                  <div className="mt-2"><StatusBadge status={selectedIncident.status} /></div>
                </div>
                <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
                  <p className="text-[9px] font-bold uppercase tracking-[0.13em] text-slate-600">Seen</p>
                  <p className="mt-2 flex items-center gap-1.5 text-[10px] font-semibold text-slate-400"><Clock3 className="h-3 w-3" /> {selectedIncident.last_seen}</p>
                </div>
              </div>

              <div className="rounded-2xl border border-slate-800 bg-slate-950/55 p-4">
                <p className="text-[10px] font-black uppercase tracking-[0.16em] text-slate-500">Primary anomaly evidence</p>
                <div className="mt-3 flex items-start gap-3">
                  <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-300" />
                  <p className="text-sm leading-6 text-slate-300">{selectedIncident.primary_reason}</p>
                </div>
              </div>

              <div className="rounded-2xl border border-slate-800 bg-slate-950/55 p-4">
                <p className="text-[10px] font-black uppercase tracking-[0.16em] text-slate-500">Context</p>
                <div className="mt-3 grid gap-3 sm:grid-cols-2">
                  <div className="flex items-center gap-3 rounded-xl border border-slate-800 bg-slate-900/60 p-3">
                    <MapPin className="h-4 w-4 text-cyan-300" />
                    <div><p className="text-[9px] uppercase tracking-[0.12em] text-slate-600">Location</p><p className="mt-1 text-xs font-semibold text-slate-300">{selectedIncident.location}</p></div>
                  </div>
                  <div className="flex items-center gap-3 rounded-xl border border-slate-800 bg-slate-900/60 p-3">
                    <Fingerprint className="h-4 w-4 text-cyan-300" />
                    <div><p className="text-[9px] uppercase tracking-[0.12em] text-slate-600">Behavior model</p><p className="mt-1 text-xs font-semibold text-slate-300">Baseline deviation detected</p></div>
                  </div>
                </div>
              </div>

              <div className="rounded-2xl border border-cyan-500/15 bg-cyan-500/[0.04] p-4">
                <div className="flex items-center gap-2 text-cyan-300">
                  <ShieldCheck className="h-4 w-4" />
                  <p className="text-[10px] font-black uppercase tracking-[0.16em]">Automated policy decision</p>
                </div>
                <p className="mt-3 text-sm leading-6 text-slate-300">{actionCopy[selectedIncident.status] || 'Incident queued for analyst review.'}</p>
                <div className="mt-4 flex items-center gap-1 text-[10px] font-bold uppercase tracking-[0.11em] text-cyan-300">
                  Explainability evidence ready <ChevronRight className="h-3.5 w-3.5" />
                </div>
              </div>
            </div>
          </aside>
        </div>
      )}

      {notice && (
        <div className="fixed bottom-5 right-5 z-[60] max-w-sm animate-slide-up rounded-xl border border-slate-700 bg-slate-900/95 px-4 py-3 shadow-2xl shadow-black/50 backdrop-blur-xl">
          <div className="flex items-center gap-3">
            {String(notice.tone).toUpperCase() === 'LOW'
              ? <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-300" />
              : <Activity className="h-4 w-4 shrink-0 text-cyan-300" />}
            <p className="text-xs font-semibold text-slate-300">{notice.message}</p>
          </div>
        </div>
      )}
    </div>
  )
}
