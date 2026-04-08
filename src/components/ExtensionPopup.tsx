import React, { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Settings, ChevronLeft, ShieldCheck, AlertTriangle, ShieldAlert, CheckCircle2, XCircle, AlertCircle, Lock, Server, Cpu, FormInput } from 'lucide-react';
import { ScenarioData } from '../App';

export default function ExtensionPopup({ scenario }: { scenario: ScenarioData }) {
  const [view, setView] = useState<'main' | 'settings'>('main');

  return (
    <div className="w-[360px] h-[580px] bg-slate-950 border border-slate-800 rounded-xl shadow-2xl overflow-hidden flex flex-col relative text-slate-50 font-sans">
      {/* Header */}
      <div className="h-14 border-b border-slate-800 flex items-center justify-between px-4 bg-slate-900/80 backdrop-blur-md z-20 shrink-0">
        <div className="flex items-center gap-2">
          {view === 'settings' ? (
            <button onClick={() => setView('main')} className="p-1.5 hover:bg-slate-800 rounded-md transition-colors -ml-1.5">
              <ChevronLeft className="w-5 h-5" />
            </button>
          ) : (
            <ShieldCheck className="w-6 h-6 text-emerald-500" />
          )}
          <span className="font-display font-semibold text-base tracking-wide">
            {view === 'settings' ? 'Settings' : 'SafeBrowse'}
          </span>
        </div>
        {view === 'main' && (
          <button onClick={() => setView('settings')} className="p-1.5 hover:bg-slate-800 rounded-md transition-colors text-slate-400 hover:text-white -mr-1.5">
            <Settings className="w-5 h-5" />
          </button>
        )}
      </div>

      {/* Content Area */}
      <div className="flex-1 relative overflow-hidden bg-slate-950">
        <AnimatePresence mode="wait">
          {view === 'main' ? (
            <MainView key="main" scenario={scenario} />
          ) : (
            <SettingsView key="settings" />
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}

function MainView({ scenario }: { scenario: ScenarioData; key?: string }) {
  const isSafe = scenario.status === 'safe';
  const isWarning = scenario.status === 'warning';
  const isDanger = scenario.status === 'danger';

  const colorClass = isSafe ? 'text-emerald-400' : isWarning ? 'text-amber-400' : 'text-red-400';
  const bgClass = isSafe ? 'bg-emerald-500/10' : isWarning ? 'bg-amber-500/10' : 'bg-red-500/10';
  const borderClass = isSafe ? 'border-emerald-500/20' : isWarning ? 'border-amber-500/20' : 'border-red-500/20';

  return (
    <motion.div 
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: -20 }}
      transition={{ duration: 0.2 }}
      className="absolute inset-0 p-4 flex flex-col overflow-y-auto custom-scrollbar"
    >
      {/* Status Hero */}
      <div className={`rounded-2xl border ${borderClass} ${bgClass} p-6 flex flex-col items-center text-center mb-6 relative overflow-hidden shrink-0`}>
        <div className={`absolute inset-0 bg-[radial-gradient(circle_at_center,_var(--tw-gradient-stops))] ${isSafe ? 'from-emerald-500/20' : isWarning ? 'from-amber-500/20' : 'from-red-500/20'} to-transparent opacity-50`}></div>
        
        <div className="relative z-10">
          <div className="w-16 h-16 mx-auto mb-4 relative">
            <div className={`absolute inset-0 rounded-full ${bgClass} animate-ping opacity-75`}></div>
            <div className={`relative w-full h-full rounded-full flex items-center justify-center bg-slate-900 border ${borderClass}`}>
              {isSafe && <ShieldCheck className={`w-8 h-8 ${colorClass}`} />}
              {isWarning && <AlertTriangle className={`w-8 h-8 ${colorClass}`} />}
              {isDanger && <ShieldAlert className={`w-8 h-8 ${colorClass}`} />}
            </div>
          </div>
          <h2 className={`text-xl font-display font-bold mb-1.5 ${colorClass}`}>{scenario.title}</h2>
          <p className="text-sm text-slate-300 leading-relaxed">{scenario.description}</p>
        </div>
      </div>

      {/* Analysis Pillars */}
      <div className="space-y-2.5 mb-6 flex-1">
        <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3 px-1">Real-Time Analysis</h3>
        
        <AnalysisRow icon={<Lock className="w-4 h-4" />} title="SSL/TLS Certificate" data={scenario.ssl} />
        <AnalysisRow icon={<Cpu className="w-4 h-4" />} title="Lexical ML Model" data={scenario.ml} />
        <AnalysisRow icon={<Server className="w-4 h-4" />} title="Safe Browsing API" data={scenario.blacklist} />
        <AnalysisRow icon={<FormInput className="w-4 h-4" />} title="Form Protection" data={scenario.forms} />
      </div>

      {/* Action / Footer */}
      <div className="mt-auto shrink-0">
        {isDanger ? (
          <div className="space-y-2">
            <button className="w-full py-2.5 rounded-xl bg-red-500 hover:bg-red-600 text-white font-semibold transition-colors shadow-lg shadow-red-500/20">
              Go Back to Safety
            </button>
            <button className="w-full py-2 rounded-xl bg-transparent hover:bg-slate-800 text-slate-400 text-sm transition-colors">
              Proceed anyway (Unsafe)
            </button>
          </div>
        ) : (
          <div className="pt-4 border-t border-slate-800/50 flex justify-between items-center text-xs text-slate-500 px-1">
            <span className="flex items-center gap-1.5">
              <ShieldCheck className="w-3.5 h-3.5" />
              Privacy-First Local Scan
            </span>
            <span className="font-mono bg-slate-800 px-2 py-0.5 rounded text-slate-400">{scenario.time}</span>
          </div>
        )}
      </div>
    </motion.div>
  );
}

function AnalysisRow({ icon, title, data }: { icon: React.ReactNode, title: string, data: { status: string, text: string } }) {
  const isSafe = data.status === 'safe';
  const isWarning = data.status === 'warning';
  const isDanger = data.status === 'danger';

  return (
    <div className="flex items-center justify-between p-3 rounded-xl bg-slate-900/50 border border-slate-800/80">
      <div className="flex items-center gap-3">
        <div className="text-slate-400 bg-slate-800 p-1.5 rounded-lg">{icon}</div>
        <div className="flex flex-col">
          <span className="text-sm font-medium text-slate-200">{title}</span>
          <span className="text-xs text-slate-500 mt-0.5">{data.text}</span>
        </div>
      </div>
      <div>
        {isSafe && <CheckCircle2 className="w-5 h-5 text-emerald-500" />}
        {isWarning && <AlertCircle className="w-5 h-5 text-amber-500" />}
        {isDanger && <XCircle className="w-5 h-5 text-red-500" />}
      </div>
    </div>
  );
}

function SettingsView() {
  return (
    <motion.div 
      initial={{ opacity: 0, x: 20 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 20 }}
      transition={{ duration: 0.2 }}
      className="absolute inset-0 p-5 flex flex-col overflow-y-auto custom-scrollbar"
    >
      <div className="space-y-6">
        <div className="space-y-4">
          <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Detection Settings</h3>
          
          <div className="flex items-center justify-between">
            <div className="pr-4">
              <div className="text-sm font-medium text-slate-200 mb-0.5">Strict ML Mode</div>
              <div className="text-xs text-slate-500 leading-relaxed">Higher sensitivity for zero-day threats. May increase false positives.</div>
            </div>
            <Toggle defaultChecked={true} />
          </div>

          <div className="flex items-center justify-between">
            <div className="pr-4">
              <div className="text-sm font-medium text-slate-200 mb-0.5">Block Insecure Forms</div>
              <div className="text-xs text-slate-500 leading-relaxed">Prevent typing in non-HTTPS forms to stop credential leaks.</div>
            </div>
            <Toggle defaultChecked={true} />
          </div>
        </div>

        <div className="space-y-4 pt-6 border-t border-slate-800/50">
          <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Privacy</h3>
          
          <div className="flex items-center justify-between">
            <div className="pr-4">
              <div className="text-sm font-medium text-slate-200 mb-0.5">Local Processing Only</div>
              <div className="text-xs text-slate-500 leading-relaxed">Never send URLs to cloud. All ML runs securely in your browser.</div>
            </div>
            <Toggle defaultChecked={true} disabled={true} />
          </div>

          <div className="flex items-center justify-between opacity-60">
            <div className="pr-4">
              <div className="text-sm font-medium text-slate-200 mb-0.5">Anonymous Telemetry</div>
              <div className="text-xs text-slate-500 leading-relaxed">Help improve ML models by sending anonymous threat signatures.</div>
            </div>
            <Toggle defaultChecked={false} />
          </div>
        </div>
      </div>

      <div className="mt-auto pt-6">
        <button className="w-full py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-sm font-medium text-slate-300 transition-colors border border-slate-700">
          View Quarantine Logs
        </button>
        <p className="text-center text-xs text-slate-600 mt-4">Version 2.1.0</p>
      </div>
    </motion.div>
  );
}

function Toggle({ defaultChecked, disabled = false }: { defaultChecked?: boolean, disabled?: boolean }) {
  const [checked, setChecked] = useState(defaultChecked);
  
  return (
    <button 
      disabled={disabled}
      onClick={() => setChecked(!checked)}
      className={`w-11 h-6 rounded-full p-1 transition-colors shrink-0 ${checked ? 'bg-emerald-500' : 'bg-slate-700'} ${disabled ? 'opacity-50 cursor-not-allowed' : ''}`}
    >
      <motion.div 
        animate={{ x: checked ? 20 : 0 }}
        className="w-4 h-4 bg-white rounded-full shadow-sm"
      />
    </button>
  );
}
