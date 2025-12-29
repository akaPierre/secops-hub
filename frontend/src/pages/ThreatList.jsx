import React, { useState, useEffect } from 'react'
import { Shield, Search, Filter, ChevronDown } from 'lucide-react'
import api from '../services/api'
import { format } from 'date-fns'

const ThreatList = () => {
  const [threats, setThreats] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [filter, setFilter] = useState('all')
  const [searchTerm, setSearchTerm] = useState('')

  useEffect(() => {
    loadThreats()
  }, [filter])

  const loadThreats = async () => {
    try {
      setLoading(true)
      const params = filter !== 'all' ? { severity: filter } : {}
      const response = await api.get('/threats/', { params })
      setThreats(response.data.data)
    } catch (err) {
      setError('Failed to load threats')
    } finally {
      setLoading(false)
    }
  }

  const handleSearch = async () => {
    if (!searchTerm.trim()) {
      loadThreats()
      return
    }

    try {
      setLoading(true)
      const response = await api.get('/threats/search', {
        params: { q: searchTerm }
      })
      setThreats(response.data.data)
    } catch (err) {
      setError('Search failed')
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

  const filteredThreats = threats

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-white mb-2">Threat Intelligence Database</h1>
        <p className="text-gray-400">Browse and search stored threat intelligence data</p>
      </div>

      {/* Filters and Search */}
      <div className="card">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Search */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              <Search className="inline h-4 w-4 mr-1" />
              Search
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
                className="input-field flex-1"
                placeholder="Search indicators..."
              />
              <button onClick={handleSearch} className="btn-primary">
                Search
              </button>
            </div>
          </div>

          {/* Filter by Severity */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              <Filter className="inline h-4 w-4 mr-1" />
              Filter by Severity
            </label>
            <select
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="input-field"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
          </div>
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/50 rounded-lg p-4 text-red-400">
          {error}
        </div>
      )}

      {/* Loading */}
      {loading && (
        <div className="flex justify-center items-center h-64">
          <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-cyber-blue"></div>
        </div>
      )}

      {/* Threats Table */}
      {!loading && (
        <div className="card">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="text-xl font-bold text-white">
              {filteredThreats.length} Threats Found
            </h2>
          </div>

          {filteredThreats.length === 0 ? (
            <div className="text-center py-12 text-gray-400">
              <Shield className="h-16 w-16 mx-auto mb-4 opacity-50" />
              <p className="text-lg">No threats found</p>
              <p className="text-sm mt-2">Try adjusting your search or filters</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-gray-700">
                    <th className="text-left py-3 px-4 text-gray-400 font-semibold">Indicator</th>
                    <th className="text-left py-3 px-4 text-gray-400 font-semibold">Type</th>
                    <th className="text-left py-3 px-4 text-gray-400 font-semibold">Severity</th>
                    <th className="text-left py-3 px-4 text-gray-400 font-semibold">Risk Score</th>
                    <th className="text-left py-3 px-4 text-gray-400 font-semibold">Source</th>
                    <th className="text-left py-3 px-4 text-gray-400 font-semibold">First Seen</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredThreats.map((threat) => (
                    <tr key={threat.id} className="border-b border-gray-800 hover:bg-cyber-dark transition-colors">
                      <td className="py-3 px-4">
                        <span className="font-mono text-cyber-blue">{threat.indicator}</span>
                      </td>
                      <td className="py-3 px-4">
                        <span className="text-gray-300 uppercase text-sm">{threat.indicator_type}</span>
                      </td>
                      <td className="py-3 px-4">
                        <span className={getSeverityBadge(threat.severity)}>
                          {threat.severity.toUpperCase()}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <span className="font-semibold text-white">{threat.risk_score}</span>
                      </td>
                      <td className="py-3 px-4">
                        <span className="text-gray-400 text-sm">{threat.source}</span>
                      </td>
                      <td className="py-3 px-4">
                        <span className="text-gray-400 text-sm">
                          {format(new Date(threat.first_seen), 'MMM dd, yyyy')}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default ThreatList