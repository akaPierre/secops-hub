import React, { useState } from 'react'
import { Search, Database, ExternalLink, AlertTriangle, Loader } from 'lucide-react'
import api from '../services/api'
import { format } from 'date-fns'

const CVESearch = () => {
  const [keyword, setKeyword] = useState('')
  const [results, setResults] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [selectedCVE, setSelectedCVE] = useState(null)

  const handleSearch = async (e) => {
    e.preventDefault()
    setError('')
    setResults(null)
    setSelectedCVE(null)
    setLoading(true)

    try {
      const response = await api.get('/threats/cve/search', {
        params: { keyword, limit: 20 }
      })
      setResults(response.data.data)
    } catch (err) {
      setError(err.response?.data?.error || 'Search failed')
    } finally {
      setLoading(false)
    }
  }

  const loadCVEDetails = async (cveId) => {
    try {
      const response = await api.get(`/threats/cve/${cveId}`)
      setSelectedCVE(response.data.data)
    } catch (err) {
      console.error('Failed to load CVE details:', err)
    }
  }

  const getSeverityColor = (severity) => {
    const colors = {
      CRITICAL: 'text-red-500 bg-red-500/20 border-red-500',
      HIGH: 'text-orange-500 bg-orange-500/20 border-orange-500',
      MEDIUM: 'text-yellow-500 bg-yellow-500/20 border-yellow-500',
      LOW: 'text-blue-500 bg-blue-500/20 border-blue-500',
      UNKNOWN: 'text-gray-500 bg-gray-500/20 border-gray-500'
    }
    return colors[severity] || colors.UNKNOWN
  }

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-white mb-2">CVE Database Search</h1>
        <p className="text-gray-400">Search the National Vulnerability Database for known security vulnerabilities</p>
      </div>

      {/* Search Form */}
      <div className="card">
        <form onSubmit={handleSearch} className="space-y-4">
          <div>
            <label htmlFor="keyword" className="block text-sm font-medium text-gray-300 mb-2">
              Search Keyword
            </label>
            <div className="flex gap-4">
              <input
                id="keyword"
                type="text"
                required
                value={keyword}
                onChange={(e) => setKeyword(e.target.value)}
                className="input-field flex-1"
                placeholder="e.g., apache, log4j, openssl, windows..."
              />
              <button
                type="submit"
                disabled={loading}
                className="btn-primary disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? (
                  <span className="flex items-center">
                    <Loader className="animate-spin h-5 w-5 mr-2" />
                    Searching...
                  </span>
                ) : (
                  <span className="flex items-center">
                    <Search className="h-5 w-5 mr-2" />
                    Search
                  </span>
                )}
              </button>
            </div>
          </div>

          <div className="flex flex-wrap gap-2">
            <span className="text-gray-400 text-sm">Quick searches:</span>
            {['apache', 'windows', 'linux', 'openssl', 'log4j', 'wordpress'].map((term) => (
              <button
                key={term}
                type="button"
                onClick={() => { setKeyword(term); }}
                className="px-3 py-1 bg-cyber-dark text-cyber-blue rounded-lg text-sm hover:bg-cyber-gray transition-colors"
              >
                {term}
              </button>
            ))}
          </div>
        </form>
      </div>

      {/* Error */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/50 rounded-lg p-4 text-red-400">
          {error}
        </div>
      )}

      {/* Results */}
      {results && (
        <div className="space-y-6">
          {/* Results Header */}
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-bold text-white">
              Found {results.total_results} vulnerabilities
            </h2>
            <div className="flex items-center text-gray-400">
              <Database className="h-5 w-5 mr-2" />
              <span>Showing {results.vulnerabilities.length} results</span>
            </div>
          </div>

          {/* CVE List */}
          <div className="grid grid-cols-1 gap-4">
            {results.vulnerabilities.map((cve) => (
              <div
                key={cve.cve_id}
                className="card hover:border-cyber-blue transition-all cursor-pointer"
                onClick={() => loadCVEDetails(cve.cve_id)}
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center mb-2">
                      <h3 className="text-lg font-bold text-cyber-blue mr-3">{cve.cve_id}</h3>
                      <span className={`px-3 py-1 rounded-full text-xs font-semibold border ${getSeverityColor(cve.severity)}`}>
                        {cve.severity}
                      </span>
                      {cve.cvss_score > 0 && (
                        <span className="ml-2 px-3 py-1 bg-cyber-dark rounded-full text-sm font-mono text-white">
                          CVSS: {cve.cvss_score}
                        </span>
                      )}
                    </div>
                    <p className="text-gray-300 text-sm mb-3 line-clamp-2">{cve.description}</p>
                    <div className="flex items-center text-xs text-gray-500 space-x-4">
                      <span>Published: {format(new Date(cve.published), 'MMM dd, yyyy')}</span>
                      {cve.references && cve.references.length > 0 && (
                        <span>{cve.references.length} references</span>
                      )}
                    </div>
                  </div>
                  <ExternalLink className="h-5 w-5 text-gray-500 flex-shrink-0 ml-4" />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* CVE Details Modal */}
      {selectedCVE && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50" onClick={() => setSelectedCVE(null)}>
          <div className="card max-w-4xl w-full max-h-[90vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-start justify-between mb-6">
              <div>
                <h2 className="text-2xl font-bold text-cyber-blue mb-2">{selectedCVE.cve_id}</h2>
                <div className="flex items-center space-x-3">
                  <span className={`px-3 py-1 rounded-full text-sm font-semibold border ${getSeverityColor(selectedCVE.severity)}`}>
                    {selectedCVE.severity}
                  </span>
                  {selectedCVE.cvss_score > 0 && (
                    <span className="px-4 py-1 bg-cyber-dark rounded-full font-mono text-white">
                      CVSS: {selectedCVE.cvss_score}
                    </span>
                  )}
                </div>
              </div>
              <button
                onClick={() => setSelectedCVE(null)}
                className="text-gray-400 hover:text-white text-2xl leading-none"
              >
                ×
              </button>
            </div>

            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-semibold text-white mb-2">Description</h3>
                <p className="text-gray-300">{selectedCVE.description}</p>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-gray-400 text-sm mb-1">Published</p>
                  <p className="text-white font-semibold">
                    {format(new Date(selectedCVE.published), 'MMMM dd, yyyy')}
                  </p>
                </div>
                <div>
                  <p className="text-gray-400 text-sm mb-1">Last Modified</p>
                  <p className="text-white font-semibold">
                    {format(new Date(selectedCVE.last_modified), 'MMMM dd, yyyy')}
                  </p>
                </div>
              </div>

              {selectedCVE.references && selectedCVE.references.length > 0 && (
                <div>
                  <h3 className="text-lg font-semibold text-white mb-3">References</h3>
                  <div className="space-y-2 max-h-60 overflow-y-auto">
                    {selectedCVE.references.slice(0, 10).map((ref, index) => (
                      <a
                        key={index}
                        href={ref.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="block p-3 bg-cyber-dark rounded-lg hover:bg-cyber-gray transition-colors group"
                      >
                        <div className="flex items-center justify-between">
                          <span className="text-cyber-blue text-sm truncate group-hover:underline">{ref.url}</span>
                          <ExternalLink className="h-4 w-4 text-gray-500 flex-shrink-0 ml-2" />
                        </div>
                      </a>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default CVESearch