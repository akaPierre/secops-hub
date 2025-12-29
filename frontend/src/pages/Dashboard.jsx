import React, { useState, useEffect } from 'react'
import { Shield, Activity, AlertTriangle, Database, TrendingUp } from 'lucide-react'
import api from '../services/api'

const Dashboard = () => {
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    loadStatistics()
  }, [])

  const loadStatistics = async () => {
    try {
      const response = await api.get('/threats/statistics')
      setStats(response.data.data)
    } catch (err) {
      setError('Failed to load statistics')
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-cyber-blue"></div>
      </div>
    )
  }

  const statCards = [
    {
      title: 'Total Threats',
      value: stats?.total_threats || 0,
      icon: Shield,
      color: 'cyber-blue',
      bgColor: 'from-blue-500/20 to-cyan-500/20'
    },
    {
      title: 'Critical',
      value: stats?.critical_count || 0,
      icon: AlertTriangle,
      color: 'red-500',
      bgColor: 'from-red-500/20 to-orange-500/20'
    },
    {
      title: 'High Severity',
      value: stats?.high_count || 0,
      icon: TrendingUp,
      color: 'orange-500',
      bgColor: 'from-orange-500/20 to-yellow-500/20'
    },
    {
      title: 'Active Threats',
      value: stats?.active_threats || 0,
      icon: Activity,
      color: 'cyber-green',
      bgColor: 'from-green-500/20 to-emerald-500/20'
    }
  ]

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-white mb-2">Security Dashboard</h1>
        <p className="text-gray-400">Real-time threat intelligence and security monitoring</p>
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/50 rounded-lg p-4 text-red-400">
          {error}
        </div>
      )}

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {statCards.map((stat, index) => {
          const Icon = stat.icon
          return (
            <div
              key={index}
              className={`stat-card bg-gradient-to-br ${stat.bgColor} hover:scale-105`}
            >
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-gray-400 text-sm font-medium mb-1">{stat.title}</p>
                  <p className="text-3xl font-bold text-white">{stat.value}</p>
                </div>
                <Icon className={`h-12 w-12 text-${stat.color}`} />
              </div>
            </div>
          )
        })}
      </div>

      {/* Severity Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity Distribution */}
        <div className="card">
          <h2 className="card-header">Threat Severity Distribution</h2>
          <div className="space-y-4">
            {[
              { label: 'Critical', value: stats?.critical_count || 0, color: 'bg-red-500', total: stats?.total_threats || 1 },
              { label: 'High', value: stats?.high_count || 0, color: 'bg-orange-500', total: stats?.total_threats || 1 },
              { label: 'Medium', value: stats?.medium_count || 0, color: 'bg-yellow-500', total: stats?.total_threats || 1 },
              { label: 'Low', value: stats?.low_count || 0, color: 'bg-blue-500', total: stats?.total_threats || 1 }
            ].map((item, index) => {
              const percentage = stats?.total_threats > 0 ? (item.value / stats.total_threats * 100).toFixed(1) : 0
              return (
                <div key={index}>
                  <div className="flex justify-between mb-2">
                    <span className="text-gray-300 font-medium">{item.label}</span>
                    <span className="text-gray-400">{item.value} ({percentage}%)</span>
                  </div>
                  <div className="w-full bg-cyber-dark rounded-full h-2">
                    <div
                      className={`${item.color} h-2 rounded-full transition-all duration-500`}
                      style={{ width: `${percentage}%` }}
                    ></div>
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* Quick Actions */}
        <div className="card">
          <h2 className="card-header">Quick Actions</h2>
          <div className="space-y-3">
            <a
              href="/threats"
              className="block p-4 bg-cyber-dark rounded-lg border border-gray-700 hover:border-cyber-blue transition-all group"
            >
              <div className="flex items-center">
                <Shield className="h-6 w-6 text-cyber-blue mr-3" />
                <div>
                  <h3 className="font-semibold text-white group-hover:text-cyber-blue">Check Threat</h3>
                  <p className="text-sm text-gray-400">Analyze IPs, domains, and hashes</p>
                </div>
              </div>
            </a>

            <a
              href="/cve"
              className="block p-4 bg-cyber-dark rounded-lg border border-gray-700 hover:border-cyber-purple transition-all group"
            >
              <div className="flex items-center">
                <Database className="h-6 w-6 text-cyber-purple mr-3" />
                <div>
                  <h3 className="font-semibold text-white group-hover:text-cyber-purple">Search CVEs</h3>
                  <p className="text-sm text-gray-400">Find known vulnerabilities</p>
                </div>
              </div>
            </a>

            <a
              href="/threats-list"
              className="block p-4 bg-cyber-dark rounded-lg border border-gray-700 hover:border-cyber-green transition-all group"
            >
              <div className="flex items-center">
                <Activity className="h-6 w-6 text-cyber-green mr-3" />
                <div>
                  <h3 className="font-semibold text-white group-hover:text-cyber-green">View All Threats</h3>
                  <p className="text-sm text-gray-400">Browse stored threat data</p>
                </div>
              </div>
            </a>
          </div>
        </div>
      </div>

      {/* System Info */}
      <div className="card">
        <h2 className="card-header">System Information</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-4 bg-cyber-dark rounded-lg">
            <p className="text-gray-400 text-sm mb-1">Indicator Types</p>
            <p className="text-2xl font-bold text-white">{stats?.indicator_types || 0}</p>
          </div>
          <div className="p-4 bg-cyber-dark rounded-lg">
            <p className="text-gray-400 text-sm mb-1">Data Sources</p>
            <p className="text-2xl font-bold text-white">{stats?.sources || 0}</p>
          </div>
          <div className="p-4 bg-cyber-dark rounded-lg">
            <p className="text-gray-400 text-sm mb-1">Active Monitoring</p>
            <p className="text-2xl font-bold text-cyber-green">Online</p>
          </div>
        </div>
      </div>
    </div>
  )
}

export default Dashboard