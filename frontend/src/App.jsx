import React, { useState } from 'react'
import axios from 'axios'
import { Search, Copy, Play, AlertCircle } from 'lucide-react'
import './App.css'

function App() {
  const [query, setQuery] = useState('')
  const [index, setIndex] = useState('')
  const [sourcetype, setSourcetype] = useState('')
  const [lookbackDays, setLookbackDays] = useState(7)
  const [splResponse, setSplResponse] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleGenerateSPL = async () => {
    if (!query.trim()) {
      setError('Please enter a query')
      return
    }

    setLoading(true)
    setError('')

    try {
      const response = await axios.post('/api/generate-spl', {
        query: query.trim(),
        index: index || undefined,
        sourcetype: sourcetype || undefined,
        lookback_days: lookbackDays
      })

      setSplResponse(response.data)
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to generate SPL')
      console.error('Error generating SPL:', err)
    } finally {
      setLoading(false)
    }
  }

  const handleCopySPL = () => {
    if (splResponse?.spl) {
      navigator.clipboard.writeText(splResponse.spl)
      // Could add toast notification here
    }
  }

  const handleRunSplunk = async () => {
    if (!splResponse?.spl) return
    
    const splunkToken = prompt('Enter your Splunk token:')
    if (!splunkToken) return

    try {
      const response = await axios.post('/api/run-splunk', {
        spl: splResponse.spl,
        splunk_token: splunkToken
      })

      alert(`Query submitted! Job ID: ${response.data.job_id}`)
      if (response.data.results_link) {
        window.open(response.data.results_link, '_blank')
      }
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to run query in Splunk')
    }
  }

  return (
    <div className="app">
      <header className="header">
        <h1>splunkLens</h1>
        <p>Natural Language → SPL Generator</p>
      </header>

      <main className="main">
        <div className="query-section">
          <div className="input-group">
            <label htmlFor="query">Natural Language Query</label>
            <textarea
              id="query"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="e.g., Show me the top 10 IP addresses with the most failed login attempts in the last 7 days"
              rows={3}
            />
          </div>

          <div className="filters">
            <div className="input-group">
              <label htmlFor="index">Index (optional)</label>
              <input
                id="index"
                type="text"
                value={index}
                onChange={(e) => setIndex(e.target.value)}
                placeholder="e.g., security, web, main"
              />
            </div>

            <div className="input-group">
              <label htmlFor="sourcetype">Sourcetype (optional)</label>
              <input
                id="sourcetype"
                type="text"
                value={sourcetype}
                onChange={(e) => setSourcetype(e.target.value)}
                placeholder="e.g., windows_security, cisco_asa"
              />
            </div>

            <div className="input-group">
              <label htmlFor="lookback">Lookback Days</label>
              <input
                id="lookback"
                type="number"
                value={lookbackDays}
                onChange={(e) => setLookbackDays(parseInt(e.target.value) || 7)}
                min={1}
                max={30}
              />
            </div>
          </div>

          <button 
            onClick={handleGenerateSPL} 
            disabled={loading || !query.trim()}
            className="generate-btn"
          >
            <Search size={16} />
            {loading ? 'Generating...' : 'Generate SPL'}
          </button>

          {error && (
            <div className="error">
              <AlertCircle size={16} />
              {error}
            </div>
          )}
        </div>

        {splResponse && (
          <div className="results-section">
            <div className="result-card">
              <h3>Generated SPL</h3>
              <div className="spl-code">
                <code>{splResponse.spl}</code>
                <button onClick={handleCopySPL} className="copy-btn">
                  <Copy size={14} />
                  Copy
                </button>
              </div>
            </div>

            <div className="result-card">
              <h3>Explanation</h3>
              <p>{splResponse.explanation}</p>
            </div>

            <div className="result-card">
              <h3>Estimate</h3>
              <div className="estimates">
                {splResponse.estimated_cost && (
                  <span>Cost: ${splResponse.estimated_cost.toFixed(2)}</span>
                )}
                {splResponse.estimated_results && (
                  <span>Results: {splResponse.estimated_results.toLocaleString()}</span>
                )}
              </div>
            </div>

            <button onClick={handleRunSplunk} className="run-btn">
              <Play size={16} />
              Run in Splunk
            </button>
          </div>
        )}
      </main>
    </div>
  )
}

export default App