import React, { useState } from 'react';
import { Fingerprint, AlertCircle, ArrowRight, Lock } from 'lucide-react';
import { api, setAuthToken } from '../services/api';
import type { User } from '../types';

interface LoginViewProps {
  onLoginSuccess: (user: User) => void;
}

export const LoginView: React.FC<LoginViewProps> = ({ onLoginSuccess }) => {
  const [email, setEmail] = useState('admin@poseidon.cti');
  const [password, setPassword] = useState('PoseidonAdmin2026!#');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const response = await api.login(email, password);
      setAuthToken(response.access_token);
      onLoginSuccess(response.user);
    } catch (err: any) {
      setError(err.message || 'Authentication failed. Please verify credentials.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-poseidon-base flex items-center justify-center p-4">
      <div className="w-full max-w-md bg-poseidon-surface border border-poseidon-border rounded-xl p-8 shadow-2xl relative overflow-hidden">
        {/* Glow Accent */}
        <div className="absolute -top-24 -right-24 w-48 h-48 bg-poseidon-cyan/10 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute -bottom-24 -left-24 w-48 h-48 bg-poseidon-gold/10 rounded-full blur-3xl pointer-events-none" />

        {/* Brand Header */}
        <div className="text-center mb-8">
          <div className="w-14 h-14 rounded-xl bg-poseidon-elevated border border-poseidon-cyan/40 mx-auto flex items-center justify-center mb-4 shadow-xl shadow-poseidon-cyan/10">
            <Fingerprint className="w-8 h-8 text-poseidon-cyan" />
          </div>
          <h1 className="text-2xl font-bold tracking-wider text-white">POSEIDON</h1>
          <p className="text-xs font-mono text-slate-400 mt-1">
            Cyber Threat Intelligence & Investigation Platform
          </p>
        </div>

        {/* Error Alert */}
        {error && (
          <div className="mb-6 p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs flex items-center gap-2.5">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-wider mb-1.5">
              Analyst Email
            </label>
            <input
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full bg-poseidon-base border border-poseidon-border rounded-lg px-3.5 py-2.5 text-xs text-white placeholder:text-slate-600 focus:outline-none focus:border-poseidon-cyan transition-colors font-mono"
              placeholder="analyst@poseidon.cti"
            />
          </div>

          <div>
            <label className="block text-[11px] font-mono text-slate-400 uppercase tracking-wider mb-1.5">
              Password
            </label>
            <input
              type="password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full bg-poseidon-base border border-poseidon-border rounded-lg px-3.5 py-2.5 text-xs text-white placeholder:text-slate-600 focus:outline-none focus:border-poseidon-cyan transition-colors font-mono"
              placeholder="••••••••••••"
            />
          </div>

          <div className="pt-2">
            <button
              type="submit"
              disabled={loading}
              className="w-full bg-poseidon-cyan text-poseidon-base font-semibold text-xs py-3 rounded-lg hover:bg-sky-400 transition-all flex items-center justify-center gap-2 disabled:opacity-50 shadow-lg shadow-poseidon-cyan/20"
            >
              {loading ? (
                <span className="font-mono">AUTHENTICATING...</span>
              ) : (
                <>
                  <span>ACCESS CONSOLE</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </div>
        </form>

        {/* Security Notice */}
        <div className="mt-8 pt-6 border-t border-poseidon-border/50 text-center">
          <div className="inline-flex items-center gap-1.5 text-[10px] font-mono text-slate-500">
            <Lock className="w-3 h-3 text-poseidon-gold" />
            <span>ENCRYPTED RBAC ENCLAVE :: TLP:AMBER STRICT</span>
          </div>
        </div>
      </div>
    </div>
  );
};
