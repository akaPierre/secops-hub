import React, { useState } from 'react'
import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { Shield, Activity, Search, Database, Menu, X, LogOut, User } from 'lucide-react'

const Layout = () => {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  const navigation = [
    { name: 'Dashboard', href: '/', icon: Activity },
    { name: 'Threat Check', href: '/threats', icon: Search },
    { name: 'CVE Search', href: '/cve', icon: Database },
    { name: 'Threats List', href: '/threats-list', icon: Shield },
  ]

  return (
    <div className="min-h-screen bg-cyber-darker">
      {/* Header */}
      <header className="bg-cyber-dark border-b border-gray-800 sticky top-0 z-50 shadow-lg">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            {/* Logo */}
            <div className="flex items-center">
              <Shield className="h-8 w-8 text-cyber-blue" />
              <span className="ml-2 text-xl font-bold text-white">
                SecOps <span className="text-cyber-blue">Hub</span>
              </span>
            </div>

            {/* Desktop Navigation */}
            <nav className="hidden md:flex space-x-1">
              {navigation.map((item) => {
                const Icon = item.icon
                return (
                  <NavLink
                    key={item.name}
                    to={item.href}
                    end={item.href === '/'}
                    className={({ isActive }) =>
                      `flex items-center px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${
                        isActive
                          ? 'bg-cyber-blue text-white shadow-lg shadow-cyan-500/50'
                          : 'text-gray-300 hover:bg-cyber-gray hover:text-white'
                      }`
                    }
                  >
                    <Icon className="h-4 w-4 mr-2" />
                    {item.name}
                  </NavLink>
                )
              })}
            </nav>

            {/* User Menu */}
            <div className="hidden md:flex items-center space-x-4">
              <div className="flex items-center text-sm">
                <User className="h-4 w-4 text-gray-400 mr-2" />
                <span className="text-gray-300">{user?.username}</span>
              </div>
              <button
                onClick={handleLogout}
                className="flex items-center text-gray-300 hover:text-cyber-red transition-colors"
              >
                <LogOut className="h-5 w-5" />
              </button>
            </div>

            {/* Mobile menu button */}
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="md:hidden text-gray-300 hover:text-white"
            >
              {mobileMenuOpen ? <X className="h-6 w-6" /> : <Menu className="h-6 w-6" />}
            </button>
          </div>
        </div>

        {/* Mobile Navigation */}
        {mobileMenuOpen && (
          <div className="md:hidden border-t border-gray-800">
            <div className="px-2 pt-2 pb-3 space-y-1">
              {navigation.map((item) => {
                const Icon = item.icon
                return (
                  <NavLink
                    key={item.name}
                    to={item.href}
                    end={item.href === '/'}
                    onClick={() => setMobileMenuOpen(false)}
                    className={({ isActive }) =>
                      `flex items-center px-3 py-2 rounded-lg text-base font-medium ${
                        isActive
                          ? 'bg-cyber-blue text-white'
                          : 'text-gray-300 hover:bg-cyber-gray hover:text-white'
                      }`
                    }
                  >
                    <Icon className="h-5 w-5 mr-3" />
                    {item.name}
                  </NavLink>
                )
              })}
              <button
                onClick={handleLogout}
                className="flex items-center w-full px-3 py-2 text-base font-medium text-gray-300 hover:text-cyber-red"
              >
                <LogOut className="h-5 w-5 mr-3" />
                Logout
              </button>
            </div>
          </div>
        )}
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <Outlet />
      </main>

      {/* Footer */}
      <footer className="bg-cyber-dark border-t border-gray-800 mt-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div className="text-center text-gray-400 text-sm">
            <p>SecOps Hub v0.3.0 | Built with React & Node.js</p>
            <p className="mt-1">
              Created by{' '}
              <a
                href="https://github.com/akaPierre"
                target="_blank"
                rel="noopener noreferrer"
                className="text-cyber-blue hover:underline"
              >
                Daniel Pierre Fachini
              </a>
            </p>
          </div>
        </div>
      </footer>
    </div>
  )
}

export default Layout