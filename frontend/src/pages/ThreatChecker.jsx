import React, { useState } from 'react'
import { Search, Shield, AlertTriangle, CheckCircle, XCircle, Loader } from 'lucide-react'
import api from '../services/api'

const ThreatChecker = () => {
  const [indicator, setIndicator] = useState('')
  const [type, setType] = useState('ip')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')

  const handleCheck = async (e) => {
    e.preventDefault()
    setError('')
    setResult(null)
    setLoading(true)

    try {
      const response = await api.post('/threats/check', {
        indicator,
        type,
        save: true
      })
      setResult(response.data.data)
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to check threat')
    } finally {
      setLoading(false)
    }
  }

  const getSeverityBadge = (severity) => {
    const classes = {
      critical: 'badge-critical',
      high: 'badge-high',
      medium: 'badge-medium',
      low: 'badge-low',
      info: 'badge-info'
    }
    return classes[severity] || 'badge-info'
  }

  const getSeverityIcon = (severity) => {
    if (severity === 'critical' || severity === 'high') {
      return <AlertTriangle className="h-5 w-5 text-red-500" />
    } else if (severity === 'medium') {
      return <AlertTriangle className="h-5 w-5 text-yellow-500" />
    } else {
      return <CheckCircle className="h-5 w-5 text-green-500" />
    }
  }

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-white mb-2">Threat Intelligence Check</h1>
        <p className="text-gray-400">Check IPs, domains, and file hashes against multiple threat intelligence sources</p>
      </div>

      {/* Search Form */}
      <div className="card">
        <form onSubmit={handleCheck} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="md:col-span-2">
              <label htmlFor="indicator" className="block text-sm font-medium text-gray-300 mb-2">
                Indicator
              </label>
              <input
                id="indicator"
                type="text"
                required
                value={indicator}
                onChange={(e) => setIndicator(e.target.value)}
                className="input-field"
                placeholder="Enter IP, domain, or hash..."
              />
            </div>

            <div>
              <label htmlFor="type" className="block text-sm font-medium text-gray-300 mb-2">
                Type
              </label>
              <select
                id="type"
                value={type}
                onChange={(e) => setType(e.target.value)}
                className="input-field"
              >
                <option value="ip">IP Address</option>
                <option value="domain">Domain</option>
                <option value="hash">File Hash</option>
                <option value="url">URL</option>
                <option value="email">Email</option>
              </select>
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="btn-primary disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? (
              <span className="flex items-center">
                <Loader className="animate-spin h-5 w-5 mr-2" />
                Checking...
              </span>
            ) : (
              <span className="flex items-center">
                <Search className="h-5 w-5 mr-2" />
                Check Threat
              </span>
            )}
          </button>
        </form>
      </div>

      {/* Error Message */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/50 rounded-lg p-4 flex items-center text-red-400">
          <XCircle className="h-5 w-5 mr-2 flex-shrink-0" />
          {error}
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="space-y-6">
          {/* Risk Assessment */}
          <div className="card border-2 border-cyber-blue">
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="flex items-center mb-4">
                  {getSeverityIcon(result.risk_assessment.severity)}
                  <h2 className="text-2xl font-bold text-white ml-3">Risk Assessment</h2>
                </div>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <p className="text-gray-400 mb-2">Indicator</p>
                    <p className="text-xl font-mono text-cyber-blue">{result.indicator}</p>
                  </div>
                  <div>
                    <p className="text-gray-400 mb-2">Type</p>
                    <p className="text-xl font-semibold text-white uppercase">{result.indicator_type}</p>
                  </div>
                  <div>
                    <p className="text-gray-400 mb-2">Risk Score</p>
                    <div className="flex items-center">
                      <p className="text-3xl font-bold text-white">{result.risk_assessment.risk_score}</p>
                      <span className="text-gray-400 ml-2">/ 100</span>
                    </div>
                  </div>
                  <div>
                    <p className="text-gray-400 mb-2">Severity</p>
                    <span className={`${getSeverityBadge(result.risk_assessment.severity)} text-lg`}>
                      {result.risk_assessment.severity.toUpperCase()}
                    </span>
                  </div>
                </div>

                <div className="mt-6 p-4 bg-cyber-dark rounded-lg">
                  <p className="text-gray-400 text-sm mb-1">Recommendation</p>
                  <p className="text-white font-semibold">{result.risk_assessment.recommendation}</p>
                </div>
              </div>
            </div>
          </div>

          {/* Source Results */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* VirusTotal */}
            {result.sources.virustotal && !result.sources.virustotal.error && (
              <div className="card">
                <h3 className="text-xl font-bold text-cyber-blue mb-4 flex items-center">
                  <Shield className="h-5 w-5 mr-2" />
                  VirusTotal
                </h3>
                <div className="space-y-3">
                  <div className="flex justify-between">
                    <span className="text-gray-400">Reputation Score</span>
                    <span className="font-semibold text-white">{result.sources.virustotal.reputation_score}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Malicious</span>
                    <span className="font-semibold text-red-400">{result.sources.virustotal.malicious}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Suspicious</span>
                    <span className="font-semibold text-orange-400">{result.sources.virustotal.suspicious}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Harmless</span>
                    <span className="font-semibold text-green-400">{result.sources.virustotal.harmless}</span>
                  </div>
                  {result.sources.virustotal.country && (
                    <div className="flex justify-between">
                      <span className="text-gray-400">Country</span>
                      <span className="font-semibold text-white">{result.sources.virustotal.country}</span>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Shodan */}
            {result.sources.shodan && !result.sources.shodan.error && (
              <div className="card">
                <h3 className="text-xl font-bold text-cyber-purple mb-4">Shodan</h3>
                <div className="space-y-3">
                  {result.sources.shodan.open_ports && result.sources.shodan.open_ports.length > 0 && (
                    <div>
                      <span className="text-gray-400">Open Ports</span>
                      <div className="flex flex-wrap gap-2 mt-2">
                        {result.sources.shodan.open_ports.slice(0, 10).map((port, i) => (
                          <span key={i} className="px-2 py-1 bg-cyber-dark rounded text-cyber-blue font-mono text-sm">
                            {port}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                  {result.sources.shodan.country && (
                    <div className="flex justify-between">
                      <span className="text-gray-400">Country</span>
                      <span className="font-semibold text-white">{result.sources.shodan.country}</span>
                    </div>
                  )}
                  {result.sources.shodan.isp && (
                    <div className="flex justify-between">
                      <span className="text-gray-400">ISP</span>
                      <span className="font-semibold text-white">{result.sources.shodan.isp}</span>
                    </div>
                  )}
                  {result.sources.shodan.vulnerabilities && result.sources.shodan.vulnerabilities.length > 0 && (
                    <div>
                      <span className="text-red-400 font-semibold">
                        {result.sources.shodan.vulnerabilities.length} Vulnerabilities Found
                      </span>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* AbuseIPDB */}
            {result.sources.abuseipdb && !result.sources.abuseipdb.error && (
              <div className="card">
                <h3 className="text-xl font-bold text-cyber-green mb-4">AbuseIPDB</h3>
                <div className="space-y-3">
                  <div className="flex justify-between">
                    <span className="text-gray-400">Abuse Score</span>
                    <span className="font-semibold text-white">{result.sources.abuseipdb.abuse_confidence_score}%</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Total Reports</span>
                    <span className="font-semibold text-white">{result.sources.abuseipdb.total_reports}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Reporters</span>
                    <span className="font-semibold text-white">{result.sources.abuseipdb.num_distinct_users}</span>
                  </div>
                  {result.sources.abuseipdb.isp && (
                    <div className="flex justify-between">
                      <span className="text-gray-400">ISP</span>
                      <span className="font-semibold text-white">{result.sources.abuseipdb.isp}</span>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Errors from sources */}
          {Object.entries(result.sources).map(([source, data]) => (
            data.error && (
              <div key={source} className="bg-yellow-500/10 border border-yellow-500/50 rounded-lg p-4">
                <p className="text-yellow-400">
                  <strong className="capitalize">{source}:</strong> {data.error}
                </p>
              </div>
            )
          ))}
        </div>
      )}
    </div>
  )
}

export default ThreatChecker