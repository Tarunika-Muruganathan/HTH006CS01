import { useCallback, useEffect, useMemo, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  Clock3,
  Fingerprint,
  MapPin,
  RefreshCw,
  Shield,
  ShieldCheck,
  ShieldX,
  Sparkles,
  X,
} from 'lucide-react'
import api from './api'
import Navbar from './components/Navbar'
import RiskBadge from './components/RiskBadge'
import StatusBadge from './components/StatusBadge'
import RiskGauge from './components/RiskGauge'
import VerificationModal from './components/VerificationModal'
import DatasetUpload from './components/DatasetUpload'
import RejectionPanel from './components/RejectionPanel'
import AIAssistant from './components/AIAssistant'
import DashboardView from './views/DashboardView'
import UsersView from './views/UsersView'
import { demoIncidents, monitoredUsers } from './data'

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
  const [backendOnline, setBackendOnline] = useState(null)
  const [lastSync, setLastSync] = useState(null)
  const [notice, setNotice] = useState(null)
  const [datasetSummary, setDatasetSummary] = useState(null)
  const [evidenceExpanded, setEvidenceExpanded] = useState(false)

  const showNotice = useCallback((message, tone = 'info') => {
    setNotice({ message, tone })
    window.setTimeout(() => setNotice(null), 3500)
  }, [])

  const checkHealth = useCallback(async () => {
    try {
      await api.get('/health')
      setBackendOnline(true)
      setLastSync(new Date())
    } catch {
      setBackendOnline(false)
    }
  }, [])

  useEffect(() => {
    checkHealth()
    const timer = window.setInterval(checkHealth, 5000)
    return () => window.clearInterval(timer)
  }, [checkHealth])

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
    <div className="min-h-screen bg-gray-950 text-slate-100 noise-overlay">
      <Navbar
        activeView={activeView}
        onNavigate={setActiveView}
      />

      <main className="mx-auto max-w-[1720px] px-4 py-6 lg:px-6">
        {/* Status Bar */}
        <motion.div
          initial={{ opacity: 0, y: -8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ type: 'spring', stiffness: 120, damping: 18, delay: 0.1 }}
          className="mb-6 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-800/50 glass px-4 py-3 text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-600 shadow-depth"
        >
          <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
            <span className="inline-flex items-center gap-2">
              <span className={`
                relative flex h-2.5 w-2.5
              `}>
                {backendOnline && (
                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-40" />
                )}
                <span className={`relative inline-flex h-2.5 w-2.5 rounded-full ${backendOnline ? 'bg-emerald-400' : backendOnline === false ? 'bg-amber-400' : 'bg-slate-600'}`} />
              </span>
              <span className={backendOnline ? 'text-emerald-300/80' : backendOnline === false ? 'text-amber-300/80' : 'text-slate-600'}>
                API {backendOnline ? 'Connected' : backendOnline === false ? 'Offline' : 'Checking'}
              </span>
            </span>
            <span className="inline-flex items-center gap-1.5">
              <Activity className="h-3.5 w-3.5 text-cyan-400/50" />
              Rule engine active
            </span>
            <span className="inline-flex items-center gap-1.5">
              <ShieldCheck className="h-3.5 w-3.5 text-emerald-400/50" />
              Enforcement armed
            </span>
          </div>
          <div className="flex items-center gap-2 font-mono normal-case tracking-normal text-slate-600">
            <RefreshCw className="h-3 w-3 animate-spin" style={{ animationDuration: '4s' }} />
            Poll 5s · last sync {syncLabel}
          </div>
        </motion.div>

        {/* Dataset upload section */}
        <DatasetUpload onLoad={(items, summary) => {
          setIncidents(items)
          setDatasetSummary(summary ?? null)
          setSelectedIncident(items[0] ?? null)
          showNotice(`Dataset analysis complete · ${items.length} records loaded`, 'LOW')
        }} />

        {datasetSummary && (
          <div className="mb-6 flex flex-wrap items-center gap-x-5 gap-y-2 rounded-xl border border-cyan-500/15 bg-cyan-500/[0.05] px-4 py-3 text-xs text-cyan-100">
            <span className="font-semibold">Uploaded dataset active</span>
            <span>{datasetSummary.records_analyzed} records analysed</span>
            {datasetSummary.files_processed && (
              <span>{datasetSummary.files_processed} files processed</span>
            )}
            <span>{datasetSummary.high_risk_records} high-priority records</span>
            <button type="button" className="ml-auto font-semibold text-cyan-300 underline underline-offset-4 hover:text-white" onClick={() => { setDatasetSummary(null); setIncidents(demoIncidents); setSelectedIncident(null) }}>Clear dataset</button>
          </div>
        )}

        {/* View Content */}
        <AnimatePresence mode="wait">
          {activeView === 'dashboard'
            ? <DashboardView key="dashboard" incidents={incidents} onInvestigate={setSelectedIncident} />
            : <UsersView key="users" users={users} />}
        </AnimatePresence>
      </main>

      {/* ─── Verification Modal ─── */}
      <VerificationModal
        open={Boolean(verificationIncident)}
        incident={verificationIncident}
        onClose={() => setVerificationIncident(null)}
        onVerified={handleVerified}
      />

      {/* ─── AI Assistant ─── */}
      <AIAssistant incident={selectedIncident} />

      {/* ─── Investigation Drawer ─── */}
      <AnimatePresence>
        {selectedIncident && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 z-40"
              style={{ background: 'rgba(3, 7, 18, 0.7)', backdropFilter: 'blur(8px)' }}
              onClick={() => { setSelectedIncident(null); setEvidenceExpanded(false) }}
            />
            <motion.aside
              initial={{ x: '100%', opacity: 0.5 }}
              animate={{ x: 0, opacity: 1 }}
              exit={{ x: '100%', opacity: 0 }}
              transition={{ type: 'spring', stiffness: 300, damping: 30 }}
              className="soc-scrollbar fixed right-0 top-0 z-40 h-full w-full max-w-xl overflow-y-auto border-l border-slate-800/60 shadow-glass-lg"
              style={{
                background: 'linear-gradient(180deg, rgba(15, 23, 42, 0.97) 0%, rgba(15, 23, 42, 0.95) 100%)',
                backdropFilter: 'blur(24px)',
              }}
              onClick={(event) => event.stopPropagation()}
            >
              {/* Header */}
              <div className="sticky top-0 z-10 border-b border-slate-800/50 p-6" style={{ background: 'rgba(15, 23, 42, 0.95)', backdropFilter: 'blur(24px)' }}>
                <div className="flex items-start justify-between gap-4">
                  <div className="flex gap-4">
                    <div className="grid h-11 w-11 shrink-0 place-items-center rounded-xl border border-slate-700/50 bg-slate-950/60 text-slate-300">
                      <SelectedIcon className="h-5 w-5" />
                    </div>
                    <div>
                      <p className="text-[10px] font-black uppercase tracking-[0.2em] text-cyan-300">
                        Investigation
                      </p>
                      <h2 className="mt-1.5 text-xl font-bold text-white">{selectedIncident.name}</h2>
                      <p className="mt-1 font-mono text-[10px] font-semibold text-slate-500">
                        {selectedIncident.user_id} · {selectedIncident.department}
                      </p>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => { setSelectedIncident(null); setEvidenceExpanded(false) }}
                    className="rounded-xl border border-transparent p-2 text-slate-600 transition-all duration-200 hover:border-slate-700 hover:bg-slate-800/60 hover:text-slate-300"
                    aria-label="Close investigation drawer"
                  >
                    <X className="h-5 w-5" />
                  </button>
                </div>
              </div>

              {/* Content */}
              <div className="space-y-5 p-6">
                {/* Risk gauge + stats */}
                <div className="flex items-center gap-6">
                  <RiskGauge value={selectedIncident.risk_score} size={100} label="Risk" />
                  <div className="grid flex-1 grid-cols-2 gap-3">
                    <div className="rounded-xl border border-slate-800/50 bg-slate-950/40 p-3">
                      <p className="text-[9px] font-bold uppercase tracking-[0.14em] text-slate-600">Level</p>
                      <div className="mt-2"><RiskBadge level={selectedIncident.level} /></div>
                    </div>
                    <div className="rounded-xl border border-slate-800/50 bg-slate-950/40 p-3">
                      <p className="text-[9px] font-bold uppercase tracking-[0.14em] text-slate-600">Status</p>
                      <div className="mt-2"><StatusBadge status={selectedIncident.status} /></div>
                    </div>
                    <div className="col-span-2 rounded-xl border border-slate-800/50 bg-slate-950/40 p-3">
                      <p className="text-[9px] font-bold uppercase tracking-[0.14em] text-slate-600">Seen</p>
                      <p className="mt-1.5 flex items-center gap-1.5 text-[11px] font-semibold text-slate-400">
                        <Clock3 className="h-3.5 w-3.5" /> {selectedIncident.last_seen}
                      </p>
                    </div>
                  </div>
                </div>

                <RejectionPanel incident={selectedIncident} />

                {/* Primary anomaly evidence */}
                <div className="rounded-2xl border border-slate-800/50 bg-slate-950/40 p-5">
                  <div className="flex items-center gap-2.5">
                    <div className="grid h-7 w-7 place-items-center rounded-lg border border-amber-500/20 bg-amber-500/10">
                      <AlertTriangle className="h-3.5 w-3.5 text-amber-300" />
                    </div>
                    <p className="text-[10px] font-black uppercase tracking-[0.18em] text-slate-500">Primary anomaly evidence</p>
                  </div>
                  <p className="mt-4 text-sm leading-7 text-slate-300">{selectedIncident.primary_reason}</p>
                </div>

                {/* Context */}
                <div className="rounded-2xl border border-slate-800/50 bg-slate-950/40 p-5">
                  <p className="text-[10px] font-black uppercase tracking-[0.18em] text-slate-500">Context</p>
                  <div className="mt-4 grid gap-3 sm:grid-cols-2">
                    <div className="flex items-center gap-3.5 rounded-xl border border-slate-800/40 bg-slate-900/40 p-3.5">
                      <div className="grid h-8 w-8 place-items-center rounded-lg border border-cyan-500/20 bg-cyan-500/10">
                        <MapPin className="h-4 w-4 text-cyan-300" />
                      </div>
                      <div>
                        <p className="text-[9px] uppercase tracking-[0.13em] text-slate-600">Location</p>
                        <p className="mt-1 text-xs font-semibold text-slate-300">{selectedIncident.location}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3.5 rounded-xl border border-slate-800/40 bg-slate-900/40 p-3.5">
                      <div className="grid h-8 w-8 place-items-center rounded-lg border border-violet-500/20 bg-violet-500/10">
                        <Fingerprint className="h-4 w-4 text-violet-300" />
                      </div>
                      <div>
                        <p className="text-[9px] uppercase tracking-[0.13em] text-slate-600">Behavior model</p>
                        <p className="mt-1 text-xs font-semibold text-slate-300">Baseline deviation detected</p>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Policy decision */}
                <div className="rounded-2xl border border-cyan-500/15 bg-cyan-500/[0.03] p-5">
                  <div className="flex items-center gap-2.5 text-cyan-300">
                    <div className="grid h-7 w-7 place-items-center rounded-lg border border-cyan-500/20 bg-cyan-500/10">
                      <ShieldCheck className="h-3.5 w-3.5" />
                    </div>
                    <p className="text-[10px] font-black uppercase tracking-[0.18em]">Automated policy decision</p>
                  </div>
                  <p className="mt-4 text-sm leading-7 text-slate-300">
                    {actionCopy[selectedIncident.status] || 'Incident queued for analyst review.'}
                  </p>

                  {/* Explainability Evidence — now functional */}
                  <button
                    type="button"
                    onClick={() => setEvidenceExpanded((prev) => !prev)}
                    className="mt-5 flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-[0.12em] text-cyan-300 transition-all duration-300 hover:gap-2.5 cursor-pointer hover:text-cyan-200"
                  >
                    <Sparkles className="h-3.5 w-3.5" />
                    {evidenceExpanded ? 'Hide explainability evidence' : 'Show explainability evidence'}
                    <ChevronRight className={`h-3.5 w-3.5 transition-transform duration-300 ${evidenceExpanded ? 'rotate-90' : ''}`} />
                  </button>

                  <AnimatePresence>
                    {evidenceExpanded && (
                      <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
                        className="overflow-hidden"
                      >
                        <div className="mt-4 space-y-3 rounded-xl border border-slate-800/40 bg-slate-950/40 p-4">
                          <div className="flex items-center gap-2">
                            <Sparkles className="h-4 w-4 text-cyan-400" />
                            <p className="text-xs font-bold text-white">Explainability Breakdown</p>
                          </div>

                          <div className="space-y-2.5 text-xs text-slate-400">
                            <div className="rounded-lg border border-slate-800/30 bg-slate-900/30 p-3">
                              <p className="text-[9px] font-bold uppercase tracking-wider text-slate-500 mb-1.5">Risk factor analysis</p>
                              <p className="leading-relaxed">{selectedIncident.primary_reason}</p>
                            </div>

                            <div className="rounded-lg border border-slate-800/30 bg-slate-900/30 p-3">
                              <p className="text-[9px] font-bold uppercase tracking-wider text-slate-500 mb-1.5">Scoring methodology</p>
                              <p className="leading-relaxed">
                                Risk score <strong className="text-white">{selectedIncident.risk_score}/100</strong> computed
                                via deterministic behavioral baselining. Score reflects deviation magnitude from the
                                user's historical activity pattern, weighted by resource sensitivity and temporal anomaly factors.
                              </p>
                            </div>

                            <div className="rounded-lg border border-slate-800/30 bg-slate-900/30 p-3">
                              <p className="text-[9px] font-bold uppercase tracking-wider text-slate-500 mb-1.5">Policy enforcement</p>
                              <p className="leading-relaxed">
                                Level <strong className="text-white">{selectedIncident.level}</strong> → Action: <strong className="text-white">{selectedIncident.status}</strong>.{' '}
                                {actionCopy[selectedIncident.status] || 'Pending review.'}
                              </p>
                            </div>

                            <div className="rounded-lg border border-slate-800/30 bg-slate-900/30 p-3">
                              <p className="text-[9px] font-bold uppercase tracking-wider text-slate-500 mb-1.5">Identity context</p>
                              <div className="grid grid-cols-2 gap-2 text-[11px]">
                                <div><span className="text-slate-500">Department:</span> <span className="text-slate-300">{selectedIncident.department}</span></div>
                                <div><span className="text-slate-500">Location:</span> <span className="text-slate-300">{selectedIncident.location}</span></div>
                                <div><span className="text-slate-500">Last seen:</span> <span className="text-slate-300">{selectedIncident.last_seen}</span></div>
                                <div><span className="text-slate-500">User ID:</span> <span className="text-cyan-400 font-mono">{selectedIncident.user_id}</span></div>
                              </div>
                            </div>
                          </div>
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              </div>
            </motion.aside>
          </>
        )}
      </AnimatePresence>

      {/* ─── Toast Notification ─── */}
      <AnimatePresence>
        {notice && (
          <motion.div
            initial={{ opacity: 0, y: 20, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 10, scale: 0.95 }}
            transition={{ type: 'spring', stiffness: 400, damping: 25 }}
            className="fixed bottom-6 left-6 z-[60] max-w-sm rounded-xl border border-slate-700/50 shadow-glass-lg"
            style={{
              background: 'rgba(15, 23, 42, 0.92)',
              backdropFilter: 'blur(16px)',
            }}
          >
            <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-white/[0.06] to-transparent" />
            <div className="flex items-center gap-3 px-5 py-4">
              {String(notice.tone).toUpperCase() === 'LOW'
                ? <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-300" />
                : <Activity className="h-4 w-4 shrink-0 text-cyan-300" />}
              <p className="text-xs font-semibold text-slate-300">{notice.message}</p>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
