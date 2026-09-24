import { useRef, useState } from 'react'
import { AlertCircle, Archive, CheckCircle2, FileUp, Sparkles, UploadCloud } from 'lucide-react'
import api from '../api'

export default function DatasetUpload({ onLoad }) {
  const [status, setStatus] = useState('idle')
  const [message, setMessage] = useState('')
  const inputRef = useRef(null)

  const handleFile = async (event) => {
    const file = event.target.files?.[0]
    if (!file) return
    setStatus('analyzing')

    const isZip = file.name.toLowerCase().endsWith('.zip')
    setMessage(
      isZip
        ? 'Extracting ZIP archive and analysing all log files…'
        : 'Reading your dataset and calculating risk scores…'
    )

    try {
      const payload = new FormData()
      payload.append('file', file)
      const { data } = await api.post('/dataset/analyze', payload, {
        headers: { 'Content-Type': 'multipart/form-data' },
        timeout: 120000,
      })
      const incidents = data?.incidents ?? []
      if (!incidents.length) throw new Error('No valid records found in this file.')
      onLoad?.(incidents, data?.summary, data?.ai_summary)
      setStatus('done')
      const filesInfo = data.summary?.files_processed
        ? ` across ${data.summary.files_processed} files`
        : ''
      setMessage(`${data.summary?.records_analyzed ?? incidents.length} records analysed${filesInfo} · ${data.summary?.high_risk_records ?? 0} need review`)
    } catch (error) {
      setStatus('error')
      setMessage(error.response?.data?.detail ?? error.message ?? 'Analysis failed. Upload a CSV, JSON, or ZIP file.')
    } finally {
      event.target.value = ''
    }
  }

  return (
    <section className="mb-6 overflow-hidden rounded-2xl border border-slate-800/60 bg-slate-950/35 shadow-glass">
      <div className="flex flex-col gap-4 p-5 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex min-w-0 items-start gap-3.5">
          <div className="grid h-10 w-10 shrink-0 place-items-center rounded-xl border border-cyan-500/20 bg-cyan-500/10">
            <UploadCloud className="h-5 w-5 text-cyan-300" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-white">Upload Log Dataset</h2>
            <p className="mt-1 max-w-2xl text-xs leading-relaxed text-slate-400">
              Upload a single log file (CSV, JSON, TXT) or a <strong className="text-cyan-300/80">ZIP archive</strong> containing multiple log files for unified analysis.
            </p>
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-3">
          <input ref={inputRef} type="file" accept=".csv,.json,.txt,.log,.zip,text/csv,application/json,application/zip" className="hidden" onChange={handleFile} />
          <button type="button" onClick={() => inputRef.current?.click()} disabled={status === 'analyzing'} className="inline-flex min-h-10 items-center gap-2 rounded-lg bg-cyan-600 px-4 py-2.5 text-xs font-bold text-white shadow-lg shadow-cyan-950/30 transition hover:bg-cyan-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-300 disabled:cursor-wait disabled:opacity-60">
            {status === 'analyzing' ? <Sparkles className="h-3.5 w-3.5 animate-pulse" /> : <FileUp className="h-3.5 w-3.5" />}
            {status === 'analyzing' ? 'Analysing…' : 'Upload dataset'}
          </button>
        </div>
      </div>
      {status !== 'idle' && <div role={status === 'error' ? 'alert' : 'status'} className={`flex items-center gap-2 border-t px-5 py-3 text-xs ${status === 'error' ? 'border-rose-500/20 bg-rose-500/[0.06] text-rose-200' : status === 'done' ? 'border-emerald-500/20 bg-emerald-500/[0.06] text-emerald-200' : 'border-cyan-500/20 bg-cyan-500/[0.06] text-cyan-100'}`}>
        {status === 'error' ? <AlertCircle className="h-3.5 w-3.5 shrink-0" /> : <CheckCircle2 className="h-3.5 w-3.5 shrink-0" />}
        {message}
      </div>}
    </section>
  )
}
