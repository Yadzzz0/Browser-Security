import React, { useState, useEffect, useCallback } from 'react';
import { createRoot } from 'react-dom/client';

// ---- Types ----
interface ScanResult {
  url: string;
  status: 'safe' | 'warning' | 'danger' | 'scanning' | 'error';
  label: string;
  confidence: number;
  phishingProbability: number;
  legitimateProbability: number;
  inferenceTimeMs: number;
  modelUsed: string;
  ssl: { status: 'safe' | 'warning' | 'danger'; text: string };
  forms: { status: 'safe' | 'warning' | 'danger'; text: string };
  timestamp: number;
}

// ---- Icons (inline SVG to avoid external asset issues) ----
const ShieldCheckIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    <polyline points="9 12 11 14 15 10"/>
  </svg>
);
const ShieldAlertIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    <line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
  </svg>
);
const AlertTriangleIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/>
    <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
  </svg>
);
const LockIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
    <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
  </svg>
);
const CpuIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/>
    <line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/>
    <line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/>
    <line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/>
    <line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/>
  </svg>
);
const FormInputIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="2" y="6" width="20" height="12" rx="2"/>
    <path d="M6 12h.01M12 12h.01M18 12h.01"/>
  </svg>
);
const CheckCircleIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
    <polyline points="22 4 12 14.01 9 11.01"/>
  </svg>
);
const XCircleIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>
  </svg>
);
const AlertCircleIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
  </svg>
);
const RefreshIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" style={{width:'16px',height:'16px'}}>
    <polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
  </svg>
);

// ---- Helper ----
function getStatusConfig(status: ScanResult['status']) {
  switch (status) {
    case 'safe':    return { color: '#10b981', bg: 'rgba(16,185,129,0.1)', border: 'rgba(16,185,129,0.2)', text: 'Connection Secure' };
    case 'warning': return { color: '#f59e0b', bg: 'rgba(245,158,11,0.1)', border: 'rgba(245,158,11,0.2)', text: 'Suspicious Site' };
    case 'danger':  return { color: '#ef4444', bg: 'rgba(239,68,68,0.1)',  border: 'rgba(239,68,68,0.2)',  text: 'Phishing Detected!' };
    case 'scanning':return { color: '#6366f1', bg: 'rgba(99,102,241,0.1)', border: 'rgba(99,102,241,0.2)', text: 'Scanning…' };
    default:        return { color: '#6b7280', bg: 'rgba(107,114,128,0.1)',border: 'rgba(107,114,128,0.2)',text: 'Scan Error' };
  }
}

function AnalysisRow({ icon, title, data }: {
  icon: React.ReactNode;
  title: string;
  data: { status: string; text: string };
}) {
  const statusIcon = data.status === 'safe'
    ? <span style={{color:'#10b981',width:20,height:20,display:'block'}}><CheckCircleIcon/></span>
    : data.status === 'warning'
    ? <span style={{color:'#f59e0b',width:20,height:20,display:'block'}}><AlertCircleIcon/></span>
    : <span style={{color:'#ef4444',width:20,height:20,display:'block'}}><XCircleIcon/></span>;

  return (
    <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',padding:'10px 12px',background:'rgba(255,255,255,0.03)',border:'1px solid rgba(255,255,255,0.08)',borderRadius:10}}>
      <div style={{display:'flex',alignItems:'center',gap:10}}>
        <div style={{color:'rgba(255,255,255,0.5)',background:'rgba(255,255,255,0.05)',padding:6,borderRadius:8,width:28,height:28,display:'flex',alignItems:'center',justifyContent:'center'}}>
          <div style={{width:14,height:14}}>{icon}</div>
        </div>
        <div>
          <div style={{fontSize:13,fontWeight:500,color:'rgba(255,255,255,0.9)'}}>{title}</div>
          <div style={{fontSize:11,color:'rgba(255,255,255,0.4)',marginTop:1}}>{data.text}</div>
        </div>
      </div>
      <div style={{width:20,height:20,flexShrink:0}}>{statusIcon}</div>
    </div>
  );
}

function ConfidenceMeter({ value, color }: { value: number; color: string }) {
  return (
    <div style={{width:'100%',height:3,background:'rgba(255,255,255,0.08)',borderRadius:2,overflow:'hidden'}}>
      <div style={{height:'100%',width:`${(value*100).toFixed(0)}%`,background:color,borderRadius:2,transition:'width 0.8s ease'}}/>
    </div>
  );
}

function App() {
  const [result, setResult] = useState<ScanResult | null>(null);
  const [tabUrl, setTabUrl] = useState<string>('');
  const [isRescanning, setIsRescanning] = useState(false);

  const loadScan = useCallback(() => {
    chrome.runtime.sendMessage({ type: 'GET_SCAN' }, (response) => {
      if (response?.result) setResult(response.result);
      if (response?.tabUrl) setTabUrl(response.tabUrl);
    });
  }, []);

  useEffect(() => {
    loadScan();
    // Poll for updates while scanning
    const interval = setInterval(() => {
      if (result?.status === 'scanning') loadScan();
    }, 1000);
    return () => clearInterval(interval);
  }, [loadScan, result?.status]);

  const handleRescan = () => {
    setIsRescanning(true);
    chrome.runtime.sendMessage({ type: 'RESCAN' }, (response) => {
      if (response?.result) setResult(response.result);
      setIsRescanning(false);
    });
  };

  const cfg = result ? getStatusConfig(result.status) : getStatusConfig('scanning');
  const displayUrl = tabUrl || result?.url || 'Loading…';
  const shortUrl = displayUrl.length > 40 ? displayUrl.substring(0, 40) + '…' : displayUrl;

  return (
    <div style={{
      width:360, height:580, background:'#020617', color:'white',
      fontFamily:'-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
      display:'flex', flexDirection:'column', overflow:'hidden',
      border:'1px solid rgba(255,255,255,0.08)', borderRadius:0,
    }}>
      {/* Header */}
      <div style={{
        height:52, display:'flex', alignItems:'center', justifyContent:'space-between',
        padding:'0 16px', borderBottom:'1px solid rgba(255,255,255,0.06)',
        background:'rgba(255,255,255,0.02)',
      }}>
        <div style={{display:'flex',alignItems:'center',gap:8}}>
          <div style={{width:22,height:22,color:'#10b981'}}><ShieldCheckIcon/></div>
          <span style={{fontWeight:700,fontSize:15,letterSpacing:'0.02em'}}>SafeBrowse</span>
        </div>
        <button
          onClick={handleRescan}
          disabled={isRescanning || result?.status === 'scanning'}
          title="Rescan this page"
          style={{
            background:'rgba(255,255,255,0.05)', border:'1px solid rgba(255,255,255,0.1)',
            color:'rgba(255,255,255,0.6)', borderRadius:8, padding:'5px 10px',
            cursor:'pointer', display:'flex', alignItems:'center', gap:5,
            fontSize:12, fontWeight:500, transition:'all 0.15s',
            opacity: (isRescanning || result?.status === 'scanning') ? 0.5 : 1,
          }}
        >
          <div style={{animation:(isRescanning||result?.status==='scanning')?'spin 1s linear infinite':undefined}}>
            <RefreshIcon/>
          </div>
          Rescan
        </button>
      </div>

      {/* URL Bar */}
      <div style={{
        padding:'8px 14px', borderBottom:'1px solid rgba(255,255,255,0.04)',
        background:'rgba(0,0,0,0.3)', display:'flex', alignItems:'center', gap:8,
      }}>
        <div style={{width:10,height:10,color:'rgba(255,255,255,0.3)',flexShrink:0}}>
          <LockIcon/>
        </div>
        <span style={{fontSize:11,color:'rgba(255,255,255,0.4)',fontFamily:'monospace',overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>
          {shortUrl}
        </span>
      </div>

      {/* Scrollable content */}
      <div style={{flex:1,overflowY:'auto',padding:16,display:'flex',flexDirection:'column',gap:14}}>
        
        {/* Status Hero Card */}
        <div style={{
          borderRadius:14, border:`1px solid ${cfg.border}`,
          background:cfg.bg, padding:20, textAlign:'center', position:'relative', overflow:'hidden',
        }}>
          {/* Radial glow */}
          <div style={{
            position:'absolute',inset:0,
            background:`radial-gradient(circle at center, ${cfg.color}22 0%, transparent 70%)`,
            pointerEvents:'none',
          }}/>
          <div style={{position:'relative'}}>
            {/* Animated icon */}
            <div style={{position:'relative',width:64,height:64,margin:'0 auto 14px'}}>
              {(result?.status === 'scanning' || result?.status === undefined) ? (
                <div style={{
                  width:64,height:64,borderRadius:'50%',border:`2px solid ${cfg.color}`,
                  borderTopColor:'transparent',animation:'spin 1s linear infinite',
                  display:'flex',alignItems:'center',justifyContent:'center',
                }}/>
              ) : (
                <>
                  <div style={{
                    position:'absolute',inset:0,borderRadius:'50%',background:cfg.bg,
                    animation:'ping 2s ease-in-out infinite',opacity:0.6,
                  }}/>
                  <div style={{
                    position:'relative',width:'100%',height:'100%',borderRadius:'50%',
                    background:'#0f172a',border:`1px solid ${cfg.border}`,
                    display:'flex',alignItems:'center',justifyContent:'center',
                  }}>
                    <div style={{width:28,height:28,color:cfg.color}}>
                      {result.status === 'safe' && <ShieldCheckIcon/>}
                      {result.status === 'warning' && <AlertTriangleIcon/>}
                      {result.status === 'danger' && <ShieldAlertIcon/>}
                      {result.status === 'error' && <AlertCircleIcon/>}
                    </div>
                  </div>
                </>
              )}
            </div>

            <h2 style={{color:cfg.color,fontSize:17,fontWeight:700,margin:'0 0 6px'}}>
              {result ? (result.status === 'scanning' ? 'Analyzing URL…' : cfg.text) : 'Initializing…'}
            </h2>

            {result && result.status !== 'scanning' && result.status !== 'error' && (
              <>
                <p style={{fontSize:12,color:'rgba(255,255,255,0.6)',margin:'0 0 12px',lineHeight:1.5}}>
                  {result.status === 'safe' && 'This site passed our AI security checks.'}
                  {result.status === 'warning' && 'Suspicious patterns detected. Proceed with caution.'}
                  {result.status === 'danger' && 'AI model flagged this as a phishing site. Do not enter credentials!'}
                </p>

                {/* Confidence bar */}
                <div style={{textAlign:'left'}}>
                  <div style={{display:'flex',justifyContent:'space-between',marginBottom:4}}>
                    <span style={{fontSize:10,color:'rgba(255,255,255,0.4)',textTransform:'uppercase',letterSpacing:'0.05em'}}>
                      {result.status === 'safe' ? 'Legitimacy' : 'Phishing Probability'}
                    </span>
                    <span style={{fontSize:10,fontFamily:'monospace',color:cfg.color}}>
                      {result.status === 'safe'
                        ? `${(result.legitimateProbability*100).toFixed(1)}%`
                        : `${(result.phishingProbability*100).toFixed(1)}%`}
                    </span>
                  </div>
                  <ConfidenceMeter
                    value={result.status === 'safe' ? result.legitimateProbability : result.phishingProbability}
                    color={cfg.color}
                  />
                </div>
              </>
            )}

            {result?.status === 'error' && (
              <p style={{fontSize:12,color:'rgba(255,255,255,0.5)',margin:0}}>
                Could not reach the SafeBrowse AI server. Check your internet connection.
              </p>
            )}
          </div>
        </div>

        {/* Analysis Rows */}
        {result && result.status !== 'scanning' && (
          <div style={{display:'flex',flexDirection:'column',gap:6}}>
            <div style={{fontSize:10,fontWeight:600,color:'rgba(255,255,255,0.3)',textTransform:'uppercase',letterSpacing:'0.08em',padding:'0 2px',marginBottom:4}}>
              Security Analysis
            </div>
            <AnalysisRow
              icon={<LockIcon/>}
              title="SSL/TLS Certificate"
              data={result.ssl}
            />
            <AnalysisRow
              icon={<CpuIcon/>}
              title="AI Model (ModernBERT)"
              data={{
                status: result.status === 'safe' ? 'safe' : result.status === 'warning' ? 'warning' : result.status === 'danger' ? 'danger' : 'safe',
                text: result.status !== 'error'
                  ? `${result.label} · ${(result.confidence*100).toFixed(1)}% confidence`
                  : 'Scan failed'
              }}
            />
            <AnalysisRow
              icon={<FormInputIcon/>}
              title="Form Protection"
              data={result.forms}
            />
          </div>
        )}

        {/* Scanning skeleton */}
        {(!result || result.status === 'scanning') && (
          <div style={{display:'flex',flexDirection:'column',gap:6}}>
            {[1,2,3].map(i => (
              <div key={i} style={{height:48,background:'rgba(255,255,255,0.03)',border:'1px solid rgba(255,255,255,0.06)',borderRadius:10,animation:'pulse 1.5s ease-in-out infinite'}}/>
            ))}
          </div>
        )}

        {/* Footer / Actions */}
        <div style={{marginTop:'auto'}}>
          {result?.status === 'danger' ? (
            <div style={{display:'flex',flexDirection:'column',gap:6}}>
              <button
                onClick={() => chrome.tabs.query({active:true,currentWindow:true}, tabs => {
                  if(tabs[0]?.id) chrome.tabs.goBack(tabs[0].id);
                })}
                style={{
                  width:'100%',padding:'11px',borderRadius:10,
                  background:'#ef4444',border:0,color:'white',
                  fontWeight:600,fontSize:13,cursor:'pointer',
                }}
              >
                ← Go Back to Safety
              </button>
              <button
                style={{
                  width:'100%',padding:'10px',borderRadius:10,
                  background:'transparent',border:'1px solid rgba(255,255,255,0.1)',
                  color:'rgba(255,255,255,0.4)',fontSize:12,cursor:'pointer',
                }}
              >
                Proceed Anyway (Unsafe)
              </button>
            </div>
          ) : result?.status && result.status !== 'scanning' ? (
            <div style={{
              paddingTop:10,borderTop:'1px solid rgba(255,255,255,0.05)',
              display:'flex',justifyContent:'space-between',alignItems:'center',
            }}>
              <span style={{fontSize:11,color:'rgba(255,255,255,0.35)',display:'flex',alignItems:'center',gap:5}}>
                <div style={{width:11,height:11,color:'#10b981'}}><ShieldCheckIcon/></div>
                Powered by ModernBERT
              </span>
              {result.inferenceTimeMs > 0 && (
                <span style={{
                  fontSize:10,fontFamily:'monospace',background:'rgba(255,255,255,0.05)',
                  border:'1px solid rgba(255,255,255,0.08)',padding:'2px 8px',borderRadius:5,
                  color:'rgba(255,255,255,0.4)',
                }}>
                  {result.inferenceTimeMs.toFixed(0)}ms
                </span>
              )}
            </div>
          ) : null}
        </div>
      </div>

      <style>{`
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
        @keyframes ping { 0%,100% { opacity:0.6; transform:scale(1); } 50% { opacity:0.2; transform:scale(1.1); } }
        @keyframes pulse { 0%,100% { opacity:0.5; } 50% { opacity:1; } }
        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.1); border-radius: 2px; }
      `}</style>
    </div>
  );
}

const root = createRoot(document.getElementById('root')!);
root.render(<App />);
