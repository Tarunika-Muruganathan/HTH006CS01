import { useState, useRef } from 'react'
import { UploadCloud, FileCheck, AlertCircle, CheckCircle2, Sparkles, X, FileText } from 'lucide-react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
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
      let normalized = []

      // Only attempt local parsing for text files to render previews
      const isTextFile = !file.name.endsWith('.zip') && !file.name.endsWith('.xlsx') && !file.name.endsWith('.xls')

      if (isTextFile) {
        try {
          const text = await file.text()
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
        } catch (err) {
          console.warn("Local parse error", err)
        }
      }

      if (isTextFile && normalized.length > 0) {
        onLoad?.(normalized)
      }

      // Automatically request backend guardrailed analysis
      setReportLoading(true)
      const formData = new FormData()
      formData.append('file', file)

      try {
        const res = await api.post('/dataset/analyze', formData)
        if (res.data?.report) {
          setReport(res.data.report)
        }
        // If it was a binary file (or even a text file) and the backend parsed users, load them!
        if (res.data?.users && res.data.users.length > 0) {
          onLoad?.(res.data.users)
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
              accept=".json,.csv,.txt,.zip,.xls,.xlsx"
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
                <Sparkles className="h-3.5 w-3.5" /> Processing & Auditing…
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
            className="w-full max-w-4xl rounded-2xl border border-cyan-900/50 bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 p-6 sm:p-8 shadow-2xl overflow-hidden text-slate-200 flex flex-col max-h-[90vh]"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between border-b border-cyan-900/30 pb-5 mb-6">
              <div className="flex items-center gap-3">
                <div className="grid h-10 w-10 place-items-center rounded-xl bg-cyan-950 border border-cyan-800 shadow-[0_0_15px_rgba(6,182,212,0.15)]">
                  <Sparkles className="h-5 w-5 text-cyan-400" />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-white tracking-wide">
                    Dataset Security Audit
                  </h2>
                  <p className="text-xs text-cyan-400/70">Automated AI Threat Analysis</p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setReportOpen(false)}
                className="rounded-xl p-2 text-slate-400 hover:bg-slate-800 hover:text-white transition-colors"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto pr-4 -mr-4 custom-scrollbar">
              <div className="prose prose-invert prose-cyan max-w-none prose-sm sm:prose-base
                prose-headings:font-bold prose-headings:tracking-tight prose-headings:text-cyan-50
                prose-h1:text-2xl prose-h2:text-xl prose-h3:text-lg prose-h3:text-cyan-300
                prose-p:text-slate-300 prose-p:leading-relaxed
                prose-a:text-cyan-400 prose-a:no-underline hover:prose-a:underline
                prose-strong:text-cyan-200 prose-strong:font-semibold
                prose-code:text-cyan-300 prose-code:bg-cyan-950/50 prose-code:px-1.5 prose-code:py-0.5 prose-code:rounded-md prose-code:before:content-none prose-code:after:content-none
                prose-pre:bg-slate-900 prose-pre:border prose-pre:border-slate-800
                prose-ul:text-slate-300 prose-ol:text-slate-300
                prose-li:marker:text-cyan-500
                bg-slate-900/40 p-6 sm:p-8 rounded-2xl border border-slate-800/60 shadow-inner"
              >
                <ReactMarkdown remarkPlugins={[remarkGfm]}>
                  {report}
                </ReactMarkdown>
              </div>
            </div>

            <div className="mt-6 pt-5 border-t border-cyan-900/30 flex justify-end gap-3">
              <button
                type="button"
                onClick={() => {
                  navigator.clipboard?.writeText(report)
                  alert('Report copied to clipboard!')
                }}
                className="px-5 py-2.5 rounded-xl border border-slate-700 bg-slate-800/50 hover:bg-slate-700 hover:border-slate-600 text-sm font-semibold text-slate-200 transition-all shadow-sm"
              >
                Copy Report
              </button>
              <button
                type="button"
                onClick={() => setReportOpen(false)}
                className="px-5 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-sm font-bold text-white shadow-[0_0_15px_rgba(6,182,212,0.3)] transition-all hover:shadow-[0_0_25px_rgba(6,182,212,0.5)]"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
