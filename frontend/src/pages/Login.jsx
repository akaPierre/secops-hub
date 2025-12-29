import React, { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { Shield, AlertCircle } from 'lucide-react'

const Login = () => {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const { login } = useAuth()
  const navigate = useNavigate()

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      await login(email, password)
      navigate('/')
    } catch (err) {
      setError(err.response?.data?.error || 'Login failed. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-cyber-darker via-cyber-dark to-cyber-darker px-4">
      <div className="max-w-md w-full">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="flex justify-center mb-4">
            <Shield className="h-16 w-16 text-cyber-blue animate-pulse-slow" />
          </div>
          <h1 className="text-4xl font-bold text-white mb-2">
            SecOps <span className="text-cyber-blue">Hub</span>
          </h1>
          <p className="text-gray-400">Security Operations Dashboard</p>
        </div>

        {/* Login Card */}
        <div className="card">
          <h2 className="text-2xl font-bold text-center mb-6 text-white">Sign In</h2>

          {error && (
            <div className="mb-4 p-3 bg-red-500/10 border border-red-500/50 rounded-lg flex items-center text-red-400">
              <AlertCircle className="h-5 w-5 mr-2 flex-shrink-0" />
              <span className="text-sm">{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-300 mb-1">
                Email
              </label>
              <input
                id="email"
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="input-field"
                placeholder="admin@secops.local"
              />
            </div>

            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-300 mb-1">
                Password
              </label>
              <input
                id="password"
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="input-field"
                placeholder="••••••••"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn-primary w-full disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? 'Signing in...' : 'Sign In'}
            </button>
          </form>

          <div className="mt-6 text-center">
            <p className="text-gray-400 text-sm">
              Don't have an account?{' '}
              <Link to="/register" className="text-cyber-blue hover:underline font-medium">
                Sign up
              </Link>
            </p>
          </div>
        </div>

        {/* Demo Info */}
        <div className="mt-6 p-4 bg-cyber-gray/50 rounded-lg border border-gray-700">
          <p className="text-gray-400 text-sm text-center">
            <strong className="text-cyber-blue">Demo Account:</strong><br />
            Email: demo@secops.local | Password: Demo123!
          </p>
        </div>
      </div>
    </div>
  )
}

export default Login