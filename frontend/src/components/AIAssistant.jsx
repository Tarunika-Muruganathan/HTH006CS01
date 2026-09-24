import { useCallback, useEffect, useRef, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Bot,
  ChevronDown,
  MessageCircle,
  Send,
  Sparkles,
  User,
  X,
} from 'lucide-react'
import api from '../api'

const WELCOME_MSG = {
  role: 'assistant',
  content: `**VectrGuard AI Assistant** 👋

I can help you investigate incidents, understand risk scores, and recommend response actions.

Try asking:
• *"What actions should I take?"*
• *"Why was this user flagged?"*
• *"Explain the risk score"*`,
}

export default function AIAssistant({ incident }) {
  const [open, setOpen] = useState(false)
  const [messages, setMessages] = useState([WELCOME_MSG])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const scrollRef = useRef(null)
  const inputRef = useRef(null)

  // Auto-scroll to bottom
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [messages, open])

  // Focus input when opened
  useEffect(() => {
    if (open) {
      window.setTimeout(() => inputRef.current?.focus(), 200)
    }
  }, [open])

  const sendMessage = useCallback(async () => {
    const text = input.trim()
    if (!text || loading) return

    const userMsg = { role: 'user', content: text }
    setMessages((prev) => [...prev, userMsg])
    setInput('')
    setLoading(true)

    try {
      const { data } = await api.post('/ai/chat', {
        message: text,
        incident_context: incident
          ? {
              user_id: incident.user_id,
              name: incident.name,
              department: incident.department,
              risk_score: incident.risk_score,
              level: incident.level,
              status: incident.status,
              location: incident.location,
              primary_reason: incident.primary_reason,
            }
          : null,
      })

      setMessages((prev) => [
        ...prev,
        { role: 'assistant', content: data.response || 'No response available.' },
      ])
    } catch {
      // Provide fallback response
      const fallback = incident
        ? `I'm analysing the incident for **${incident.name}** (${incident.user_id}).

**Risk Level:** ${incident.level} (Score: ${incident.risk_score}/100)
**Status:** ${incident.status}

**Key finding:** ${incident.primary_reason}

I recommend reviewing the user's recent activity logs and verifying their identity through an out-of-band channel.`
        : `I'm here to help with incident investigation. Please select an incident to investigate, and I can provide contextual analysis and recommendations.`

      setMessages((prev) => [
        ...prev,
        { role: 'assistant', content: fallback },
      ])
    } finally {
      setLoading(false)
    }
  }, [input, loading, incident])

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      sendMessage()
    }
  }

  // Simple markdown-like rendering for bold text and bullet points
  const renderContent = (text) => {
    return text.split('\n').map((line, i) => {
      // Bold text
      let processed = line.replace(/\*\*(.*?)\*\*/g, '<strong class="text-white font-semibold">$1</strong>')
      // Italic text
      processed = processed.replace(/\*(.*?)\*/g, '<em class="text-cyan-200/80">$1</em>')
      // Bullet points
      if (processed.startsWith('• ') || processed.startsWith('- ')) {
        return (
          <div key={i} className="flex gap-2 pl-1">
            <span className="mt-0.5 shrink-0 text-cyan-400/60">•</span>
            <span dangerouslySetInnerHTML={{ __html: processed.replace(/^[•\-]\s*/, '') }} />
          </div>
        )
      }
      if (!processed.trim()) return <div key={i} className="h-2" />
      return <p key={i} dangerouslySetInnerHTML={{ __html: processed }} />
    })
  }

  return (
    <>
      {/* Floating toggle button */}
      <AnimatePresence>
        {!open && (
          <motion.button
            initial={{ scale: 0, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0, opacity: 0 }}
            transition={{ type: 'spring', stiffness: 400, damping: 25 }}
            onClick={() => setOpen(true)}
            className="fixed bottom-6 right-6 z-50 grid h-14 w-14 place-items-center rounded-2xl border border-cyan-500/30 bg-gradient-to-br from-cyan-600 to-cyan-500 text-white shadow-lg shadow-cyan-900/40 transition-all duration-300 hover:scale-105 hover:shadow-xl hover:shadow-cyan-900/50"
            aria-label="Open AI Assistant"
          >
            <MessageCircle className="h-6 w-6" />
            <span className="absolute -right-1 -top-1 flex h-4 w-4">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-50" />
              <span className="relative inline-flex h-4 w-4 rounded-full border-2 border-gray-950 bg-emerald-400" />
            </span>
          </motion.button>
        )}
      </AnimatePresence>

      {/* Chat panel */}
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: 20, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 20, scale: 0.95 }}
            transition={{ type: 'spring', stiffness: 300, damping: 28 }}
            className="fixed bottom-6 right-6 z-50 flex w-[420px] max-w-[calc(100vw-48px)] flex-col overflow-hidden rounded-2xl border border-slate-700/50 shadow-2xl"
            style={{
              height: 'min(600px, calc(100vh - 120px))',
              background: 'linear-gradient(180deg, rgba(15, 23, 42, 0.98) 0%, rgba(10, 15, 26, 0.98) 100%)',
              backdropFilter: 'blur(24px)',
            }}
          >
            {/* Header */}
            <div className="flex shrink-0 items-center justify-between border-b border-slate-800/60 px-5 py-4">
              <div className="flex items-center gap-3">
                <div className="grid h-9 w-9 place-items-center rounded-xl border border-cyan-500/25 bg-cyan-500/10">
                  <Bot className="h-4.5 w-4.5 text-cyan-300" />
                </div>
                <div>
                  <p className="text-sm font-bold text-white">AI Assistant</p>
                  <p className="text-[10px] font-semibold uppercase tracking-[0.12em] text-emerald-400/80">
                    <span className="mr-1.5 inline-block h-1.5 w-1.5 rounded-full bg-emerald-400" />
                    Online
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setOpen(false)}
                className="rounded-lg border border-transparent p-2 text-slate-500 transition-all duration-200 hover:border-slate-700 hover:bg-slate-800/60 hover:text-slate-300"
                aria-label="Close AI Assistant"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {/* Incident context banner */}
            {incident && (
              <div className="shrink-0 border-b border-slate-800/40 bg-slate-900/40 px-5 py-2.5 text-[10px]">
                <span className="font-bold uppercase tracking-wider text-slate-500">Context: </span>
                <span className="font-semibold text-cyan-300">{incident.name}</span>
                <span className="text-slate-600"> · {incident.user_id} · </span>
                <span className={`font-bold ${
                  incident.level === 'CRITICAL' ? 'text-rose-400' :
                  incident.level === 'HIGH' ? 'text-orange-400' :
                  incident.level === 'MEDIUM' ? 'text-amber-400' : 'text-emerald-400'
                }`}>{incident.level}</span>
              </div>
            )}

            {/* Messages */}
            <div
              ref={scrollRef}
              className="soc-scrollbar flex-1 overflow-y-auto px-4 py-4 space-y-4"
            >
              {messages.map((msg, idx) => (
                <motion.div
                  key={idx}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.05 }}
                  className={`flex gap-3 ${msg.role === 'user' ? 'flex-row-reverse' : ''}`}
                >
                  <div className={`mt-1 grid h-7 w-7 shrink-0 place-items-center rounded-lg border ${
                    msg.role === 'user'
                      ? 'border-violet-500/20 bg-violet-500/10'
                      : 'border-cyan-500/20 bg-cyan-500/10'
                  }`}>
                    {msg.role === 'user'
                      ? <User className="h-3.5 w-3.5 text-violet-300" />
                      : <Sparkles className="h-3.5 w-3.5 text-cyan-300" />
                    }
                  </div>
                  <div className={`max-w-[85%] rounded-2xl px-4 py-3 text-xs leading-relaxed ${
                    msg.role === 'user'
                      ? 'bg-violet-500/10 border border-violet-500/15 text-slate-200'
                      : 'bg-slate-800/40 border border-slate-700/30 text-slate-300'
                  }`}>
                    {renderContent(msg.content)}
                  </div>
                </motion.div>
              ))}

              {/* Typing indicator */}
              {loading && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="flex gap-3"
                >
                  <div className="grid h-7 w-7 shrink-0 place-items-center rounded-lg border border-cyan-500/20 bg-cyan-500/10">
                    <Sparkles className="h-3.5 w-3.5 text-cyan-300 animate-pulse" />
                  </div>
                  <div className="flex items-center gap-1.5 rounded-2xl bg-slate-800/40 border border-slate-700/30 px-4 py-3">
                    <span className="h-2 w-2 rounded-full bg-cyan-400/60 animate-bounce" style={{ animationDelay: '0ms' }} />
                    <span className="h-2 w-2 rounded-full bg-cyan-400/60 animate-bounce" style={{ animationDelay: '150ms' }} />
                    <span className="h-2 w-2 rounded-full bg-cyan-400/60 animate-bounce" style={{ animationDelay: '300ms' }} />
                  </div>
                </motion.div>
              )}
            </div>

            {/* Input */}
            <div className="shrink-0 border-t border-slate-800/60 p-4">
              <div className="flex items-end gap-2.5">
                <div className="flex-1 rounded-xl border border-slate-700/50 bg-slate-900/60 transition-all duration-300 focus-within:border-cyan-500/30 focus-within:shadow-[0_0_12px_rgba(34,211,238,0.06)]">
                  <textarea
                    ref={inputRef}
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    onKeyDown={handleKeyDown}
                    placeholder="Ask about this incident…"
                    rows={1}
                    className="w-full resize-none bg-transparent px-4 py-3 text-xs text-slate-200 outline-none placeholder:text-slate-600"
                    style={{ maxHeight: '80px' }}
                  />
                </div>
                <button
                  type="button"
                  onClick={sendMessage}
                  disabled={!input.trim() || loading}
                  className="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-cyan-600 text-white transition-all duration-300 hover:bg-cyan-500 disabled:opacity-30 disabled:cursor-not-allowed"
                  aria-label="Send message"
                >
                  <Send className="h-4 w-4" />
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  )
}
