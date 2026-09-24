import { useState, useRef } from 'react'
import { UploadCloud, FileCheck, AlertCircle, CheckCircle2 } from 'lucide-react'

export default function DatasetUpload({ onLoad }) {
  const [status, setStatus] = useState('idle') // idle | parsing | done | error
  const inputRef = useRef(null)

  const handleFile = async (e) => {
    const file = e.target.files?.[0]
    if (!file) return
    setStatus('parsing')
    try {
      const text = await file.text()
      const data = JSON.parse(text)
      // Expect array of objects matching backend incident schema
      const normalized = Array.isArray(data) ? data.map((item) => ({
        user_id: item.user_id ?? item.userId ?? item.employee_id ?? 'UNKNOWN',
        name: item.name ?? item.user_name ?? 'Unknown',
        department: item.department ?? item.dept ?? 'Unknown',
        risk_score: Number(item.risk_score ?? item.score ?? 0),
        level: String(item.level ?? item.risk_level ?? 'LOW').toUpperCase(),
        location: item.location ?? item.source_location ?? 'Unknown',
        primary_reason: item.primary_reason ?? item.reason ?? item.explanation ?? 'Anomaly detected',
        status: String(item.status ?? 'APPROVED').toUpperCase(),
        last_seen: item.last_seen ?? item.timestamp ?? 'just now',
      })) : []
      onLoad?.(normalized)
      setStatus('done')
    } catch {
      setStatus('error')
    }
  }

  return (
    <div className="rounded-2xl border border-slate-800/60 bg-slate-950/40 p-5 shadow-glass">
      <div className="flex items-center gap-3">
        <div className="grid h-10 w-10 place-items-center rounded-xl border border-cyan-500/20 bg-cyan-500/10">
          <UploadCloud className="h-5 w-5 text-cyan-300" />
        </div>
        <div>
          <h3 className="text-sm font-bold text-white">Dataset upload</h3>
          <p className="text-xs text-slate-500">JSON array of identity records (user_id, risk_score, level, primary_reason)</p>
        </div>
      </div>

      <div className="mt-4 flex items-center gap-3">
        <button
          type="button"
          onClick={() => inputRef.current?.click()}
          className="inline-flex items-center gap-2 rounded-lg bg-cyan-600/90 px-4 py-2.5 text-xs font-bold text-white shadow-lg shadow-cyan-900/20 transition hover:bg-cyan-500"
        >
          <FileCheck className="h-3.5 w-3.5" /> Choose file
        </button>
        <input ref={inputRef} type="file" accept=".json,.txt" className="hidden" onChange={handleFile} />
        {status === 'done' && <span className="inline-flex items-center gap-1.5 text-xs font-medium text-emerald-300"><CheckCircle2 className="h-3.5 w-3.5" /> Parsed</span>}
        {status === 'error' && <span className="inline-flex items-center gap-1.5 text-xs font-medium text-rose-300"><AlertCircle className="h-3.5 w-3.5" /> Invalid JSON</span>}
        {status === 'parsing' && <span className="text-xs text-slate-400">Parsing…</span>}
      </div>
    </div>
  )
}
