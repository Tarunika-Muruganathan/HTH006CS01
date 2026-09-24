import { useState, useRef } from 'react'
import { UploadCloud, FileCheck, AlertCircle, CheckCircle2, Sparkles, X, FileText } from 'lucide-react'
import api from '../api'

export default function DatasetUpload({ onLoad }) {
  const [status, setStatus] = useState('idle') // idle | parsing | done | error
  const [reportLoading, setReportLoading] = useState(false)
  const [report, setReport] = useState(null)
  const [reportOpen, setReportOpen] = useState(false)
  const inputRef = useRef(null)

  const handleFile = async (e) => {
    const file = e.target.files?.[0]
    if (!file) return
    setStatus('parsing')
    try {
      const text = await file.text()
      let normalized = []

      // Try JSON parsing
      try {
        const data = JSON.parse(text)
        const items = Array.isArray(data) ? data : data?.records || data?.items || []
        normalized = items.map((item) => ({
          user_id: item.user_id ?? item.userId ?? item.employee_id ?? 'UNKNOWN',
          name: item.name ?? item.user_name ?? 'Unknown',
          department: item.department ?? item.dept ?? 'Unknown',
          risk_score: Number(item.risk_score ?? item.score ?? 0),
          level: String(item.level ?? item.risk_level ?? 'LOW').toUpperCase(),
          location: item.location ?? item.source_location ?? 'Unknown',
          primary_reason: item.primary_reason ?? item.reason ?? item.explanation ?? 'Anomaly detected',
          status: String(item.status ?? 'APPROVED').toUpperCase(),
          last_seen: item.last_seen ?? item.timestamp ?? 'just now',
        }))
      } catch {
        // If CSV, basic normalization
        const lines = text.split('\n').filter(Boolean)
        if (lines.length > 1) {
          const headers = lines[0].split(',').map(h => h.trim().toLowerCase())
          normalized = lines.slice(1, 30).map((line, idx) => {
            const vals = line.split(',')
            const getVal = (key) => {
              const i = headers.indexOf(key)
              return i !== -1 ? vals[i]?.trim() : null
            }
            return {
              user_id: getVal('user_id') || `CUST-${idx + 101}`,
              name: getVal('name') || `User ${idx + 101}`,
              department: getVal('department') || 'Enterprise',
              risk_score: Number(getVal('risk_score') || 45),
              level: getVal('level') || 'MEDIUM',
              location: getVal('location') || 'Customer Telemetry',
              primary_reason: getVal('primary_reason') || 'Customer dataset ingestion event',
              status: getVal('status') || 'VERIFYING',
              last_seen: 'just now',
            }
          })
        }
      }

      if (normalized.length > 0) {
        onLoad?.(normalized)
      }

      // Automatically request backend guardrailed analysis
      setReportLoading(true)
      const formData = new FormData()
      formData.append('file', file)

      try {
        const res = await api.post('/dataset/analyze', formData, {
          headers: { 'Content-Type': 'multipart/form-data' },
        })
        if (res.data?.report) {
          setReport(res.data.report)
        }
      } catch (err) {
        console.warn('Backend dataset analyze failed, continuing with client parse:', err)
      } finally {
        setReportLoading(false)
      }

      setStatus('done')
    } catch {
      setStatus('error')
    }
  }

  return (
    <>
      <div className="mb-6 rounded-2xl border border-slate-800/60 bg-slate-950/40 p-5 shadow-glass">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="grid h-10 w-10 place-items-center rounded-xl border border-cyan-500/20 bg-cyan-500/10">
              <UploadCloud className="h-5 w-5 text-cyan-300" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                Customer Dataset Processing & Audit
                <span className="rounded-full bg-cyan-500/10 px-2 py-0.5 text-[10px] font-bold text-cyan-400 border border-cyan-500/20">
                  Guardrailed AI
                </span>
              </h3>
              <p className="text-xs text-slate-500">
                Upload customer logs (JSON or CSV). Isolated analysis ensures existing models remain unaffected.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button
              type="button"
              onClick={() => inputRef.current?.click()}
              className="inline-flex items-center gap-2 rounded-lg bg-cyan-600/90 px-4 py-2.5 text-xs font-bold text-white shadow-lg shadow-cyan-900/20 transition hover:bg-cyan-500 cursor-pointer"
            >
              <FileCheck className="h-3.5 w-3.5" /> Select Dataset
            </button>
            <input
              ref={inputRef}
              type="file"
              accept=".json,.csv,.txt"
              className="hidden"
              onChange={handleFile}
            />

            {status === 'done' && (
              <span className="inline-flex items-center gap-1.5 text-xs font-medium text-emerald-300">
                <CheckCircle2 className="h-3.5 w-3.5" /> Dataset Loaded
              </span>
            )}
            {status === 'error' && (
              <span className="inline-flex items-center gap-1.5 text-xs font-medium text-rose-300">
                <AlertCircle className="h-3.5 w-3.5" /> Parse Failed
              </span>
            )}
            {(status === 'parsing' || reportLoading) && (
              <span className="inline-flex items-center gap-1.5 text-xs text-cyan-300 animate-pulse">
                <Sparkles className="h-3.5 w-3.5" /> Processing & Guardrailing…
              </span>
            )}

            {report && (
              <button
                type="button"
                onClick={() => setReportOpen(true)}
                className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-500/30 bg-cyan-950/40 px-3.5 py-2 text-xs font-semibold text-cyan-300 hover:bg-cyan-900/50 transition cursor-pointer"
              >
                <FileText className="h-3.5 w-3.5" /> View Security Report
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Report Modal */}
      {reportOpen && report && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4"
          style={{ background: 'rgba(3, 7, 18, 0.8)', backdropFilter: 'blur(8px)' }}
          onClick={() => setReportOpen(false)}
        >
          <div
            className="w-full max-w-3xl rounded-2xl border border-slate-700/60 bg-slate-900/95 p-6 shadow-2xl overflow-hidden text-slate-200"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-4">
              <div className="flex items-center gap-2">
                <Sparkles className="h-5 w-5 text-cyan-400" />
                <h2 className="text-base font-bold text-white">
                  Guardrailed Dataset Security Audit
                </h2>
              </div>
              <button
                type="button"
                onClick={() => setReportOpen(false)}
                className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-800 hover:text-white"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="max-h-[65vh] overflow-y-auto pr-2 space-y-4 font-mono text-xs leading-relaxed whitespace-pre-wrap bg-slate-950/80 p-5 rounded-xl border border-slate-800/80">
              {report}
            </div>

            <div className="mt-4 flex justify-end gap-3">
              <button
                type="button"
                onClick={() => {
                  navigator.clipboard?.writeText(report)
                  alert('Report copied to clipboard!')
                }}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200"
              >
                Copy Report
              </button>
              <button
                type="button"
                onClick={() => setReportOpen(false)}
                className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-xs font-bold text-white"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
