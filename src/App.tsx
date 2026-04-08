import { useState } from 'react';
import ExtensionPopup from './components/ExtensionPopup';
import AdminDashboard from './components/AdminDashboard';
import { Shield, AlertTriangle, ShieldAlert, Info, Lock, LayoutDashboard, Chrome } from 'lucide-react';

export type Status = 'safe' | 'warning' | 'danger';

export interface ScenarioData {
  id: string;
  label: string;
  url: string;
  status: Status;
  title: string;
  description: string;
  ssl: { status: Status; text: string };
  ml: { status: Status; text: string };
  blacklist: { status: Status; text: string };
  forms: { status: Status; text: string };
  time: string;
}

export const scenarios: ScenarioData[] = [
  {
    id: 'safe',
    label: 'Legitimate Website',
    url: 'https://github.com/login',
    status: 'safe',
    title: 'Connection Secure',
    description: 'This website is verified and safe to use.',
    ssl: { status: 'safe', text: 'Valid Certificate (DigiCert)' },
    ml: { status: 'safe', text: 'Clean Lexical Pattern' },
    blacklist: { status: 'safe', text: 'Not Listed' },
    forms: { status: 'safe', text: 'Forms Secured (HTTPS)' },
    time: '42ms'
  },
  {
    id: 'suspicious',
    label: 'Zero-Day Phishing (Typosquatting)',
    url: 'https://g1thub-support.com/auth',
    status: 'warning',
    title: 'Suspicious Site',
    description: 'ML detected high entropy and typosquatting patterns.',
    ssl: { status: 'safe', text: 'Valid (Let\'s Encrypt)' },
    ml: { status: 'warning', text: 'High Entropy / Typosquatting' },
    blacklist: { status: 'safe', text: 'Not Listed (Zero-Day)' },
    forms: { status: 'safe', text: 'Forms Secured (HTTPS)' },
    time: '128ms'
  },
  {
    id: 'dangerous',
    label: 'Known Malicious Site',
    url: 'https://secure-update-paypal-verify.com',
    status: 'danger',
    title: 'Phishing Detected!',
    description: 'This site is a known phishing threat. Do not proceed.',
    ssl: { status: 'warning', text: 'Self-Signed Certificate' },
    ml: { status: 'danger', text: 'Malicious Signature Match' },
    blacklist: { status: 'danger', text: 'Flagged by Safe Browsing' },
    forms: { status: 'danger', text: 'Credential Harvesting Detected' },
    time: '86ms'
  },
  {
    id: 'insecure_form',
    label: 'Insecure Login Form',
    url: 'http://local-credit-union.com/login',
    status: 'danger',
    title: 'Insecure Connection',
    description: 'Passwords submitted here will be sent in plain text.',
    ssl: { status: 'danger', text: 'No SSL/TLS (HTTP)' },
    ml: { status: 'safe', text: 'Clean Lexical Pattern' },
    blacklist: { status: 'safe', text: 'Not Listed' },
    forms: { status: 'danger', text: 'Unencrypted Password Field' },
    time: '34ms'
  }
];

export default function App() {
  const [activeScenario, setActiveScenario] = useState(scenarios[0]);
  const [viewMode, setViewMode] = useState<'extension' | 'admin'>('admin');

  if (viewMode === 'admin') {
    return (
      <div className="relative">
        <ViewToggle viewMode={viewMode} setViewMode={setViewMode} />
        <AdminDashboard />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#050505] flex items-center justify-center p-4 md:p-8 font-sans text-slate-50 relative">
      <ViewToggle viewMode={viewMode} setViewMode={setViewMode} />
      
      <div className="max-w-6xl w-full grid lg:grid-cols-2 gap-12 lg:gap-24 items-center mt-16">
        {/* Left side: Controls */}
        <div className="space-y-8 order-2 lg:order-1">
          <div>
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-sm font-medium mb-6">
              <Shield className="w-4 h-4" />
              <span>Chrome Extension Preview</span>
            </div>
            <h1 className="text-4xl md:text-5xl font-display font-bold mb-6 leading-tight">
              Test the <span className="text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 to-cyan-400">SafeBrowse</span> UI
            </h1>
            <p className="text-lg text-slate-400 leading-relaxed">
              Select a scenario below to see how the extension reacts in real-time. 
              All analysis runs locally in the browser, ensuring your privacy is never compromised.
            </p>
          </div>

          <div className="space-y-3">
            {scenarios.map(s => (
              <button
                key={s.id}
                onClick={() => setActiveScenario(s)}
                className={`w-full flex items-center gap-4 p-4 rounded-xl border transition-all duration-200 ${
                  activeScenario.id === s.id 
                    ? 'bg-white/10 border-white/20 shadow-lg scale-[1.02]' 
                    : 'bg-white/[0.02] border-white/5 hover:bg-white/[0.05] hover:border-white/10'
                }`}
              >
                <div className={`w-12 h-12 rounded-full flex items-center justify-center shrink-0 ${
                  s.status === 'safe' ? 'bg-emerald-500/20 text-emerald-400' :
                  s.status === 'warning' ? 'bg-amber-500/20 text-amber-400' :
                  'bg-red-500/20 text-red-400'
                }`}>
                  {s.status === 'safe' ? <Shield className="w-6 h-6" /> :
                   s.status === 'warning' ? <AlertTriangle className="w-6 h-6" /> :
                   <ShieldAlert className="w-6 h-6" />}
                </div>
                <div className="text-left overflow-hidden">
                  <div className="font-semibold text-white text-lg mb-0.5">{s.label}</div>
                  <div className="text-sm text-slate-400 truncate">{s.url}</div>
                </div>
              </button>
            ))}
          </div>
          
          <div className="flex items-start gap-3 p-4 rounded-xl bg-blue-500/10 border border-blue-500/20 text-blue-400 text-sm">
            <Info className="w-5 h-5 shrink-0 mt-0.5" />
            <p>This is an interactive preview of the Chrome Extension popup. In a real environment, it automatically scans the active tab.</p>
          </div>
        </div>

        {/* Right side: Extension */}
        <div className="flex justify-center order-1 lg:order-2">
          <div className="relative">
            {/* Decorative browser chrome */}
            <div className="absolute -inset-6 border border-white/10 rounded-[2rem] bg-white/[0.02] -z-10 backdrop-blur-xl shadow-2xl hidden md:block">
              <div className="h-12 border-b border-white/5 flex items-center px-6 gap-2">
                <div className="flex gap-2">
                  <div className="w-3 h-3 rounded-full bg-red-500/80"></div>
                  <div className="w-3 h-3 rounded-full bg-amber-500/80"></div>
                  <div className="w-3 h-3 rounded-full bg-emerald-500/80"></div>
                </div>
                <div className="ml-6 flex-1 h-7 bg-black/50 border border-white/10 rounded-md flex items-center px-3">
                  <Lock className="w-3 h-3 text-white/40 mr-2" />
                  <span className="text-xs text-white/60 truncate font-mono">{activeScenario.url}</span>
                </div>
              </div>
            </div>
            
            {/* Actual Extension Popup */}
            <ExtensionPopup scenario={activeScenario} />
          </div>
        </div>
      </div>
    </div>
  );
}

function ViewToggle({ viewMode, setViewMode }: { viewMode: 'extension' | 'admin', setViewMode: (mode: 'extension' | 'admin') => void }) {
  return (
    <div className="absolute top-6 left-1/2 -translate-x-1/2 z-50 flex p-1 bg-white/5 backdrop-blur-md border border-white/10 rounded-full shadow-2xl">
      <button 
        onClick={() => setViewMode('extension')}
        className={`flex items-center gap-2 px-4 py-2 rounded-full text-sm font-medium transition-all ${
          viewMode === 'extension' ? 'bg-white text-black shadow-sm' : 'text-white/60 hover:text-white hover:bg-white/5'
        }`}
      >
        <Chrome className="w-4 h-4" />
        Extension Preview
      </button>
      <button 
        onClick={() => setViewMode('admin')}
        className={`flex items-center gap-2 px-4 py-2 rounded-full text-sm font-medium transition-all ${
          viewMode === 'admin' ? 'bg-white text-black shadow-sm' : 'text-white/60 hover:text-white hover:bg-white/5'
        }`}
      >
        <LayoutDashboard className="w-4 h-4" />
        Admin Portal
      </button>
    </div>
  );
}
