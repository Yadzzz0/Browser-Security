import React, { useState, useMemo, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { HashRouter, Routes, Route, useNavigate, useParams } from 'react-router-dom';
import { 
  ShieldCheck, Activity, Users, Database, Settings, Bell, Search, 
  ArrowUpRight, ArrowDownRight, ShieldAlert, Cpu, Globe, AlertTriangle,
  Laptop, Monitor, Power, RefreshCw, CheckCircle2, XCircle, Info, MoreVertical, Filter,
  ArrowLeft, Server, Terminal
} from 'lucide-react';
import { 
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  BarChart, Bar
} from 'recharts';

// --- Mock Data ---

const threatData = [
  { time: '00:00', phishing: 120, malware: 40, blocked: 150 },
  { time: '04:00', phishing: 180, malware: 60, blocked: 220 },
  { time: '08:00', phishing: 450, malware: 120, blocked: 540 },
  { time: '12:00', phishing: 600, malware: 200, blocked: 780 },
  { time: '16:00', phishing: 550, malware: 180, blocked: 710 },
  { time: '20:00', phishing: 300, malware: 90, blocked: 370 },
  { time: '24:00', phishing: 150, malware: 50, blocked: 190 },
];

const recentThreats = [
  { id: 'TR-8921', time: '10:42:05', url: 'secure-update-paypal-verify.com', type: 'Phishing', confidence: '99.8%', action: 'Blocked' },
  { id: 'TR-8920', time: '10:41:12', url: 'g1thub-support.com/auth', type: 'Typosquatting', confidence: '94.2%', action: 'Warned' },
  { id: 'TR-8919', time: '10:38:55', url: 'apple-id-recovery-urgent.net', type: 'Phishing', confidence: '98.5%', action: 'Blocked' },
  { id: 'TR-8918', time: '10:35:20', url: 'local-credit-union.com/login', type: 'Insecure Form', confidence: '100%', action: 'Blocked' },
  { id: 'TR-8917', time: '10:31:04', url: 'netflix-billing-update-now.info', type: 'Phishing', confidence: '97.1%', action: 'Blocked' },
];

const endpointsData = [
  { id: 'EP-1042', hostname: 'DESKTOP-DEV-01', ip: '192.168.1.42', os: 'Windows 11', status: 'Active', risk: 'Low', lastSeen: 'Just now', deploymentStatus: 'Success' },
  { id: 'EP-1043', hostname: 'MAC-DESIGN-04', ip: '192.168.1.105', os: 'macOS 14.2', status: 'Active', risk: 'Low', lastSeen: '2m ago', deploymentStatus: 'Success' },
  { id: 'EP-1044', hostname: 'SRV-PROD-DB', ip: '10.0.0.5', os: 'Ubuntu 22.04', status: 'Warning', risk: 'Medium', lastSeen: 'Just now', deploymentStatus: 'Failed' },
  { id: 'EP-1045', hostname: 'LAPTOP-SALES-12', ip: '192.168.1.210', os: 'Windows 10', status: 'Offline', risk: 'High', lastSeen: '4h ago', deploymentStatus: 'Pending' },
  { id: 'EP-1046', hostname: 'MAC-EXEC-01', ip: '192.168.1.15', os: 'macOS 14.1', status: 'Active', risk: 'Low', lastSeen: 'Just now', deploymentStatus: 'Success' },
];

const initialNotifications = [
  { id: 1, title: 'High Risk Threat Blocked', desc: 'Zero-day phishing attempt blocked on EP-1045.', time: '2m ago', type: 'alert', read: false },
  { id: 2, title: 'ML Model Updated', desc: 'Lexical analysis model v2.4 deployed successfully.', time: '1h ago', type: 'info', read: false },
  { id: 3, title: 'Endpoint Offline', desc: 'LAPTOP-SALES-12 has been offline for > 4 hours.', time: '4h ago', type: 'warning', read: true },
  { id: 4, title: 'Weekly Report Ready', desc: 'Security overview for Week 12 is available.', time: '1d ago', type: 'success', read: true },
];

// --- Supabase Client ---
import { createClient, type Session } from '@supabase/supabase-js';

const supabaseUrl = (import.meta as any).env.VITE_SUPABASE_URL || 'https://placeholder.supabase.co';
const supabaseKey = (import.meta as any).env.VITE_SUPABASE_ANON_KEY || 'placeholder';
const supabase = createClient(supabaseUrl, supabaseKey);

type UserRole = 'admin' | 'user';

interface ManagedUser {
  id: string;
  email: string;
  display_name?: string | null;
  role: UserRole;
  created_at?: string;
}

function parseRole(value: unknown): UserRole | null {
  if (value === 'admin' || value === 'user') return value;
  return null;
}

async function ensureUserProfileRow(session: Session): Promise<void> {
  const displayName =
    (session.user.user_metadata?.display_name as string | undefined) ||
    (session.user.email ? session.user.email.split('@')[0] : 'User');

  const withRole = await supabase.from('user_profiles').upsert(
    {
      id: session.user.id,
      email: session.user.email,
      display_name: displayName,
      role: 'user',
    },
    { onConflict: 'id' }
  );

  if (!withRole.error) return;

  // Fallback for schemas that don't yet contain a role column.
  await supabase.from('user_profiles').upsert(
    {
      id: session.user.id,
      email: session.user.email,
      display_name: displayName,
    },
    { onConflict: 'id' }
  );
}

async function resolveUserRole(session: Session): Promise<UserRole> {
  const metadataRole = parseRole(session.user.user_metadata?.role);
  if (metadataRole) return metadataRole;

  const adminById = await supabase.from('admin_users').select('id').eq('id', session.user.id).maybeSingle();
  if (adminById.data) return 'admin';

  if (session.user.email) {
    const adminByEmail = await supabase
      .from('admin_users')
      .select('id')
      .eq('email', session.user.email)
      .maybeSingle();
    if (adminByEmail.data) return 'admin';
  }

  const profileById = await supabase.from('user_profiles').select('role').eq('id', session.user.id).maybeSingle();
  const profileRole = parseRole(profileById.data?.role);
  if (profileRole) return profileRole;

  await ensureUserProfileRow(session);
  return 'user';
}

// --- Auth Component ---
function LoginScreen() {
  const [mode, setMode] = useState<'login' | 'signup'>('login');
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [info, setInfo] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setInfo('');

    if (mode === 'login') {
      const { error: loginError } = await supabase.auth.signInWithPassword({ email, password });
      if (loginError) setError(loginError.message);
      setLoading(false);
      return;
    }

    const safeName = fullName.trim() || (email.includes('@') ? email.split('@')[0] : 'User');
    const { data, error: signUpError } = await supabase.auth.signUp({
      email,
      password,
      options: {
        data: {
          role: 'user',
          display_name: safeName,
        },
      },
    });

    if (signUpError) {
      setError(signUpError.message);
      setLoading(false);
      return;
    }

    if (data.user) {
      const profileInsert = {
        id: data.user.id,
        email: data.user.email,
        display_name: safeName,
        role: 'user',
      };

      const withRole = await supabase.from('user_profiles').upsert(profileInsert, { onConflict: 'id' });
      if (withRole.error) {
        await supabase.from('user_profiles').upsert(
          { id: data.user.id, email: data.user.email, display_name: safeName },
          { onConflict: 'id' }
        );
      }
    }

    setInfo('Signup successful. If email confirmation is enabled, please verify your email and then login.');
    setMode('login');
    setLoading(false);
  };

  return (
    <div className="min-h-screen bg-[#050505] text-white flex items-center justify-center p-4">
      <div className="w-full max-w-md p-8 glass-panel border border-white/10 rounded-2xl relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-br from-emerald-500/10 to-transparent opacity-50 pointer-events-none" />
        <div className="relative">
          <div className="flex items-center justify-center mb-8">
            <ShieldCheck className="w-10 h-10 text-emerald-500 mr-3" />
            <span className="font-display font-bold text-2xl tracking-tight">SafeBrowse<span className="text-emerald-500">.Portal</span></span>
          </div>

          <div className="grid grid-cols-2 gap-2 bg-black/30 rounded-lg p-1 mb-5">
            <button
              type="button"
              onClick={() => { setMode('login'); setError(''); setInfo(''); }}
              className={`py-2 rounded-md text-sm transition-colors ${mode === 'login' ? 'bg-emerald-500 text-black font-semibold' : 'text-white/70 hover:text-white'}`}
            >
              Login
            </button>
            <button
              type="button"
              onClick={() => { setMode('signup'); setError(''); setInfo(''); }}
              className={`py-2 rounded-md text-sm transition-colors ${mode === 'signup' ? 'bg-emerald-500 text-black font-semibold' : 'text-white/70 hover:text-white'}`}
            >
              Sign Up
            </button>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            {mode === 'signup' && (
              <div>
                <label className="block text-sm text-white/60 mb-1.5 ml-1">Full Name</label>
                <input type="text" value={fullName} onChange={e => setFullName(e.target.value)}
                  className="w-full bg-black/50 border border-white/10 rounded-lg px-4 py-3 text-sm text-white outline-none focus:border-emerald-500/50 transition-colors"
                  placeholder="John Doe" />
              </div>
            )}
            <div>
              <label className="block text-sm text-white/60 mb-1.5 ml-1">Email</label>
              <input type="email" required value={email} onChange={e => setEmail(e.target.value)}
                className="w-full bg-black/50 border border-white/10 rounded-lg px-4 py-3 text-sm text-white outline-none focus:border-emerald-500/50 transition-colors"
                placeholder="user@safebrowse.com" />
            </div>
            <div>
              <label className="block text-sm text-white/60 mb-1.5 ml-1">Password</label>
              <input type="password" required value={password} onChange={e => setPassword(e.target.value)}
                className="w-full bg-black/50 border border-white/10 rounded-lg px-4 py-3 text-sm text-white outline-none focus:border-emerald-500/50 transition-colors"
                placeholder="••••••••" />
            </div>
            {error && <div className="text-red-400 text-sm bg-red-500/10 p-3 rounded-lg border border-red-500/20">{error}</div>}
            {info && <div className="text-emerald-300 text-sm bg-emerald-500/10 p-3 rounded-lg border border-emerald-500/20">{info}</div>}
            <button type="submit" disabled={loading}
              className="w-full py-3 mt-4 bg-emerald-500 hover:bg-emerald-400 text-black font-semibold rounded-lg transition-colors flex justify-center items-center">
              {loading ? <RefreshCw className="w-5 h-5 animate-spin" /> : mode === 'login' ? 'Secure Login' : 'Create Account'}
            </button>
          </form>
          <div className="mt-6 text-center text-xs text-white/40">
            User accounts can sign up here.<br/>Admin accounts should be created and role-assigned in Supabase.
          </div>
        </div>
      </div>
    </div>
  );
}

// --- Main Component ---

export default function AdminDashboard() {
  const [session, setSession] = useState<Session | null>(null);
  const [role, setRole] = useState<UserRole | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let isMounted = true;

    const syncAuthState = async (nextSession: Session | null) => {
      if (!isMounted) return;
      setSession(nextSession);

      if (!nextSession) {
        setRole(null);
        setLoading(false);
        return;
      }

      setLoading(true);
      const resolvedRole = await resolveUserRole(nextSession);
      if (!isMounted) return;
      setRole(resolvedRole);
      setLoading(false);
    };

    void supabase.auth.getSession().then(({ data: { session: initialSession } }) => syncAuthState(initialSession));

    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, nextSession) => {
      void syncAuthState(nextSession);
    });

    return () => {
      isMounted = false;
      subscription.unsubscribe();
    };
  }, []);

  if (loading) return <div className="min-h-screen bg-[#050505] text-white flex items-center justify-center"><RefreshCw className="w-6 h-6 animate-spin text-emerald-500 mr-2"/> Authenticating...</div>;
  if (!session) return <LoginScreen />;
  if (role === 'user') return <UserDashboard session={session} onSignOut={() => supabase.auth.signOut()} />;

  return (
    <HashRouter>
      <Routes>
        <Route path="/" element={<DashboardLayout session={session} />} />
        <Route path="/endpoint/:id" element={<EndpointDetailView />} />
      </Routes>
    </HashRouter>
  );
}

function DashboardLayout({ session }: { session: Session }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [showNotifications, setShowNotifications] = useState(false);
  const [notifications, setNotifications] = useState(initialNotifications);
  const [filterType, setFilterType] = useState('all');
  const [filterStatus, setFilterStatus] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const navigate = useNavigate();

  const unreadCount = notifications.filter(n => !n.read).length;

  const markAllRead = () => {
    setNotifications(notifications.map(n => ({ ...n, read: true })));
  };

  const markAsRead = (id: number) => {
    setNotifications(notifications.map(n => n.id === id ? { ...n, read: true } : n));
  };

  const filteredNotifications = notifications.filter(n => {
    if (filterType !== 'all' && n.type !== filterType) return false;
    if (filterStatus === 'unread' && n.read) return false;
    if (filterStatus === 'read' && !n.read) return false;
    return true;
  });

  return (
    <div className="min-h-screen bg-[#050505] text-white font-sans flex overflow-hidden">
      {/* Sidebar */}
      <aside className="w-64 border-r border-white/5 bg-white/[0.01] flex flex-col shrink-0">
        <div className="h-16 flex items-center px-6 border-b border-white/5">
          <ShieldCheck className="w-6 h-6 text-emerald-500 mr-2" />
          <span className="font-display font-bold text-lg tracking-tight">SafeBrowse<span className="text-emerald-500">.Enterprise</span></span>
        </div>
        
        <nav className="flex-1 py-6 px-3 space-y-1">
          <NavItem icon={<Activity />} label="Overview" active={activeTab === 'overview'} onClick={() => setActiveTab('overview')} />
          <NavItem icon={<Monitor />} label="Endpoints" active={activeTab === 'endpoints'} onClick={() => setActiveTab('endpoints')} />
          <NavItem icon={<Users />} label="Users" active={activeTab === 'users'} onClick={() => setActiveTab('users')} />
          <NavItem icon={<ShieldAlert />} label="Threat Intel" active={activeTab === 'threats'} onClick={() => setActiveTab('threats')} />
          <NavItem icon={<Cpu />} label="ML Models" active={activeTab === 'models'} onClick={() => setActiveTab('models')} />
          <NavItem icon={<Database />} label="Data Logs" active={activeTab === 'logs'} onClick={() => setActiveTab('logs')} />
        </nav>
        
        <div className="p-4 border-t border-white/5 space-y-1">
          <NavItem icon={<Settings />} label="Settings" active={activeTab === 'settings'} onClick={() => setActiveTab('settings')} />
          <button onClick={() => supabase.auth.signOut()} className="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium text-red-400 hover:bg-red-500/10 transition-colors">
            <Power className="w-4 h-4 shrink-0" /> Sign Out
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col h-screen overflow-hidden">
        {/* Topbar */}
        <header className="h-16 border-b border-white/5 bg-white/[0.01] flex items-center justify-between px-8 shrink-0">
          <div className="flex items-center bg-white/5 rounded-full px-4 py-1.5 border border-white/5 w-96">
            <Search className="w-4 h-4 text-white/40 mr-2" />
            <input 
              type="text" 
              placeholder="Search IPs, URLs, or Endpoint IDs..." 
              className="bg-transparent border-none outline-none text-sm w-full text-white placeholder:text-white/30 font-mono"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>
          
          <div className="flex items-center gap-6">
            <div className="relative">
              <button 
                onClick={() => setShowNotifications(!showNotifications)} 
                className={`relative transition-colors ${showNotifications ? 'text-white' : 'text-white/60 hover:text-white'}`}
              >
                <Bell className="w-5 h-5" />
                {unreadCount > 0 && (
                  <span className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-emerald-500 rounded-full border-2 border-[#050505]"></span>
                )}
              </button>

              {/* Notification Center Dropdown */}
              <AnimatePresence>
                {showNotifications && (
                  <motion.div 
                    initial={{ opacity: 0, y: 10, scale: 0.95 }}
                    animate={{ opacity: 1, y: 0, scale: 1 }}
                    exit={{ opacity: 0, y: 10, scale: 0.95 }}
                    transition={{ duration: 0.2 }}
                    className="absolute right-0 top-full mt-4 w-96 glass-panel shadow-2xl z-50 overflow-hidden border border-white/10 flex flex-col max-h-[32rem]"
                  >
                    <div className="p-4 border-b border-white/5 flex flex-col gap-3 bg-white/[0.02] shrink-0">
                      <div className="flex justify-between items-center">
                        <h3 className="font-display font-semibold text-sm">Notifications</h3>
                        {unreadCount > 0 && (
                          <button onClick={markAllRead} className="text-xs text-emerald-400 hover:text-emerald-300 transition-colors">
                            Mark all read
                          </button>
                        )}
                      </div>
                      
                      {/* Filters */}
                      <div className="flex gap-2 text-xs">
                        <select 
                          value={filterType} 
                          onChange={(e) => setFilterType(e.target.value)}
                          className="bg-white/5 border border-white/10 rounded px-2 py-1 text-white/70 outline-none focus:border-emerald-500/50"
                        >
                          <option value="all">All Types</option>
                          <option value="alert">Alerts</option>
                          <option value="warning">Warnings</option>
                          <option value="info">Info</option>
                          <option value="success">Success</option>
                        </select>
                        <select 
                          value={filterStatus} 
                          onChange={(e) => setFilterStatus(e.target.value)}
                          className="bg-white/5 border border-white/10 rounded px-2 py-1 text-white/70 outline-none focus:border-emerald-500/50"
                        >
                          <option value="all">All Status</option>
                          <option value="unread">Unread</option>
                          <option value="read">Read</option>
                        </select>
                      </div>
                    </div>
                    
                    <div className="overflow-y-auto custom-scrollbar flex-1">
                      {filteredNotifications.length === 0 ? (
                        <div className="p-8 text-center text-white/40 text-sm">No notifications match filters</div>
                      ) : (
                        filteredNotifications.map(n => (
                          <div 
                            key={n.id} 
                            className={`p-4 border-b border-white/5 hover:bg-white/[0.02] transition-colors flex gap-3 ${n.read ? 'opacity-60' : ''}`}
                            onClick={() => !n.read && markAsRead(n.id)}
                          >
                            <div className="shrink-0 mt-0.5">
                              {n.type === 'alert' && <ShieldAlert className="w-4 h-4 text-red-400" />}
                              {n.type === 'warning' && <AlertTriangle className="w-4 h-4 text-amber-400" />}
                              {n.type === 'info' && <Info className="w-4 h-4 text-blue-400" />}
                              {n.type === 'success' && <CheckCircle2 className="w-4 h-4 text-emerald-400" />}
                            </div>
                            <div className="flex-1">
                              <div className="flex justify-between items-start mb-1">
                                <h4 className={`text-sm font-medium ${n.read ? 'text-white/70' : 'text-white'}`}>{n.title}</h4>
                                <span className="text-[10px] font-mono text-white/40 whitespace-nowrap ml-2">{n.time}</span>
                              </div>
                              <p className="text-xs text-white/50 leading-relaxed mb-2">{n.desc}</p>
                              
                              {/* Actionable Buttons for Alerts */}
                              {n.type === 'alert' && (
                                <div className="flex gap-2 mt-2">
                                  <button className="px-3 py-1.5 bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/20 rounded text-xs font-medium transition-colors flex items-center gap-1.5">
                                    <Power className="w-3 h-3" /> Isolate
                                  </button>
                                  <button className="px-3 py-1.5 bg-white/5 hover:bg-white/10 text-white/70 border border-white/10 rounded text-xs font-medium transition-colors">
                                    View Threat
                                  </button>
                                </div>
                              )}

                              {/* Actionable Buttons for Warnings */}
                              {n.type === 'warning' && (
                                <div className="flex gap-2 mt-2">
                                  <button 
                                    onClick={(e) => { 
                                      e.stopPropagation(); 
                                      setActiveTab('endpoints'); 
                                      setShowNotifications(false); 
                                    }}
                                    className="px-3 py-1.5 bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 border border-amber-500/20 rounded text-xs font-medium transition-colors flex items-center gap-1.5"
                                  >
                                    <Monitor className="w-3 h-3" /> View Endpoint Details
                                  </button>
                                </div>
                              )}
                            </div>
                          </div>
                        ))
                      )}
                    </div>
                    <div className="p-3 border-t border-white/5 bg-white/[0.01] text-center shrink-0">
                      <button className="text-xs text-white/40 hover:text-white transition-colors">View All History</button>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>

            <div className="flex items-center gap-3 pl-6 border-l border-white/10 cursor-pointer">
              <div className="w-8 h-8 rounded-full bg-gradient-to-tr from-emerald-500 to-cyan-500 flex items-center justify-center text-xs font-bold text-white shadow-lg">
                {session?.user?.email?.charAt(0).toUpperCase() || 'A'}
              </div>
              <div className="flex flex-col">
                <span className="text-sm font-medium">Administrator</span>
                <span className="text-xs text-white/40 font-mono truncate max-w-[120px]" title={session?.user?.email}>{session?.user?.email}</span>
              </div>
            </div>
          </div>
        </header>

        {/* Dynamic View Content */}
        <div className="flex-1 overflow-y-auto custom-scrollbar p-8">
          {activeTab === 'overview' && <OverviewView />}
          {activeTab === 'endpoints' && <EndpointsView searchQuery={searchQuery} />}
          {activeTab === 'users' && <UsersManagementView />}
          {activeTab === 'threats' && <ThreatIntelView />}
          {activeTab === 'models' && <MLModelsView />}
          {activeTab === 'logs' && <DataLogsView />}
          {activeTab === 'settings' && <SettingsView />}
        </div>
      </main>
    </div>
  );
}

// --- New Sub-Views ---

function useUserThreats(userId: string) {
  const [logs, setLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchUserLogs() {
      setLoading(true);

      let userScopedRows: any[] = [];

      const byUserId = await supabase
        .from('scan_logs')
        .select('*')
        .eq('user_id', userId)
        .order('created_at', { ascending: false })
        .limit(200);

      if (!byUserId.error && byUserId.data) {
        userScopedRows = byUserId.data;
      } else {
        const ownerRows = await supabase.from('endpoint_owners').select('endpoint_id').eq('user_id', userId);
        const endpointIds = (ownerRows.data || []).map((row: any) => row.endpoint_id).filter(Boolean);
        if (endpointIds.length > 0) {
          const byEndpoint = await supabase
            .from('scan_logs')
            .select('*')
            .in('endpoint_id', endpointIds)
            .order('created_at', { ascending: false })
            .limit(200);
          if (!byEndpoint.error && byEndpoint.data) {
            userScopedRows = byEndpoint.data;
          }
        }
      }

      const mapped = userScopedRows.map((row: any) => ({
        id: String(row.id || '').slice(0, 8),
        time: new Date(row.created_at).toLocaleTimeString(),
        date: new Date(row.created_at).toLocaleDateString(),
        url: (row.url || '').replace(/^https?:\/\//, ''),
        action: row.action_taken || (row.status === 'danger' ? 'Blocked' : row.status === 'warning' ? 'Warned' : 'Passed'),
        confidence: `${Math.round((row.confidence || 0) * 1000) / 10}%`,
        endpoint_id: row.endpoint_id || 'Unknown',
      }));

      setLogs(mapped);
      setLoading(false);
    }

    if (userId) {
      void fetchUserLogs();
      const timer = setInterval(fetchUserLogs, 7000);
      return () => clearInterval(timer);
    }
  }, [userId]);

  return { logs, loading };
}

function UserDashboard({ session, onSignOut }: { session: Session; onSignOut: () => void | Promise<unknown> }) {
  const { logs, loading } = useUserThreats(session.user.id);
  const [endpointIdInput, setEndpointIdInput] = useState('');
  const [linking, setLinking] = useState(false);
  const [linkMessage, setLinkMessage] = useState('');

  const blockedCount = logs.filter((row) => row.action === 'Blocked').length;
  const warnedCount = logs.filter((row) => row.action === 'Warned').length;

  const handleLinkEndpoint = async () => {
    const endpointId = endpointIdInput.trim();
    if (!endpointId) {
      setLinkMessage('Enter a valid endpoint ID first.');
      return;
    }

    setLinking(true);
    setLinkMessage('');

    const response = await fetch('/api/link-endpoint', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ endpointId, userId: session.user.id }),
    });
    const payload = await response.json();

    if (!response.ok) {
      setLinkMessage(payload?.detail || payload?.error || 'Failed to link endpoint.');
      setLinking(false);
      return;
    }

    const linkedCount = typeof payload?.linkedScanCount === 'number' ? payload.linkedScanCount : 0;
    const warning = payload?.ownerWarning ? ` ${payload.ownerWarning}` : '';
    setLinkMessage(`Endpoint linked successfully. ${linkedCount} existing scan(s) were associated.${warning}`);
    setEndpointIdInput('');
    setLinking(false);
  };

  return (
    <div className="min-h-screen bg-[#050505] text-white p-6 md:p-8">
      <div className="max-w-7xl mx-auto">
        <div className="flex flex-col md:flex-row md:items-end md:justify-between gap-4 mb-8">
          <div>
            <h1 className="text-3xl font-display font-bold mb-2">User Security Portal</h1>
            <p className="text-white/40">Track phishing URLs encountered by your account and endpoints.</p>
          </div>
          <button
            onClick={() => onSignOut()}
            className="px-4 py-2 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-sm font-medium hover:bg-red-500/20 transition-colors flex items-center gap-2"
          >
            <Power className="w-4 h-4" /> Sign Out
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
          <div className="glass-panel p-5">
            <div className="text-sm text-white/40 mb-1">Signed In As</div>
            <div className="font-mono text-sm text-emerald-300 break-all">{session.user.email}</div>
          </div>
          <div className="glass-panel p-5">
            <div className="text-sm text-white/40 mb-1">Total Scans</div>
            <div className="text-2xl font-bold font-mono">{logs.length}</div>
          </div>
          <div className="glass-panel p-5">
            <div className="text-sm text-white/40 mb-1">Threat Actions</div>
            <div className="text-sm font-mono text-red-400">Blocked: {blockedCount} | Warned: {warnedCount}</div>
          </div>
        </div>

        <div className="glass-panel p-5 mb-8">
          <h2 className="font-display font-semibold mb-2">Link Endpoint to Your Account</h2>
          <p className="text-sm text-white/50 mb-4">
            Paste your extension endpoint ID (example: EP-abc12345) to associate scan logs with your user account.
          </p>
          <div className="flex flex-col md:flex-row gap-3">
            <input
              type="text"
              value={endpointIdInput}
              onChange={(e) => setEndpointIdInput(e.target.value)}
              placeholder="EP-xxxxxxxx"
              className="flex-1 bg-black/40 border border-white/10 rounded-lg px-4 py-2.5 text-sm text-white outline-none focus:border-emerald-500/50"
            />
            <button
              onClick={() => void handleLinkEndpoint()}
              disabled={linking}
              className="px-4 py-2.5 rounded-lg bg-emerald-500 text-black font-semibold text-sm hover:bg-emerald-400 disabled:opacity-60 transition-colors"
            >
              {linking ? 'Linking...' : 'Link Endpoint'}
            </button>
          </div>
          {linkMessage && <p className="mt-3 text-sm text-emerald-300">{linkMessage}</p>}
        </div>

        <div className="glass-panel overflow-hidden">
          <div className="p-4 border-b border-white/10 bg-white/[0.02] font-display font-semibold">Your Recent Scan Logs</div>
          <div className="grid grid-cols-[100px_110px_2fr_1fr_1fr_1fr] gap-3 p-4 border-b border-white/10 text-xs font-semibold text-white/40 uppercase tracking-wider bg-black/20">
            <div>Log ID</div>
            <div>Time</div>
            <div>URL</div>
            <div>Endpoint</div>
            <div>Action</div>
            <div>Confidence</div>
          </div>

          {loading ? (
            <div className="p-8 text-center text-white/40">Loading your security activity...</div>
          ) : logs.length === 0 ? (
            <div className="p-8 text-center text-white/30">No user-linked logs yet. Once scans are linked to your account, they appear here.</div>
          ) : (
            logs.map((row) => (
              <div key={row.id + row.time} className="grid grid-cols-[100px_110px_2fr_1fr_1fr_1fr] gap-3 p-4 border-b border-white/5 items-center hover:bg-white/[0.02] transition-colors">
                <div className="font-mono text-xs text-white/50">{row.id}</div>
                <div className="font-mono text-xs text-white/50">{row.time}</div>
                <div className="font-mono text-sm text-white/80 truncate pr-2">{row.url}</div>
                <div className="font-mono text-xs text-blue-300">{row.endpoint_id}</div>
                <div className={`text-xs font-medium ${row.action === 'Blocked' ? 'text-red-400' : row.action === 'Warned' ? 'text-amber-400' : 'text-emerald-400'}`}>{row.action}</div>
                <div className="font-mono text-xs text-emerald-300">{row.confidence}</div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

function UsersManagementView() {
  const [users, setUsers] = useState<ManagedUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [savingUserId, setSavingUserId] = useState<string | null>(null);
  const [canEditRole, setCanEditRole] = useState(true);

  const loadUsers = async () => {
    setLoading(true);
    setError('');

    const withRole = await supabase
      .from('user_profiles')
      .select('id,email,display_name,role,created_at')
      .order('created_at', { ascending: false })
      .limit(300);

    if (!withRole.error && withRole.data) {
      setCanEditRole(true);
      setUsers(
        withRole.data.map((row: any) => ({
          id: row.id,
          email: row.email || 'unknown@user',
          display_name: row.display_name,
          role: parseRole(row.role) || 'user',
          created_at: row.created_at,
        }))
      );
      setLoading(false);
      return;
    }

    const fallback = await supabase
      .from('user_profiles')
      .select('id,email,display_name,created_at')
      .order('created_at', { ascending: false })
      .limit(300);

    if (fallback.error) {
      setError(fallback.error.message);
      setUsers([]);
      setLoading(false);
      return;
    }

    setCanEditRole(false);
    setUsers(
      (fallback.data || []).map((row: any) => ({
        id: row.id,
        email: row.email || 'unknown@user',
        display_name: row.display_name,
        role: 'user',
        created_at: row.created_at,
      }))
    );
    setLoading(false);
  };

  useEffect(() => {
    void loadUsers();
  }, []);

  const handleRoleChange = async (userId: string, nextRole: UserRole) => {
    if (!canEditRole) return;
    setSavingUserId(userId);
    const result = await supabase.from('user_profiles').update({ role: nextRole }).eq('id', userId);
    if (result.error) {
      setError(result.error.message);
      setSavingUserId(null);
      return;
    }
    setUsers((prev) => prev.map((user) => (user.id === userId ? { ...user, role: nextRole } : user)));
    setSavingUserId(null);
  };

  const filteredUsers = users.filter((user) => {
    if (!search) return true;
    const q = search.toLowerCase();
    return (
      user.email.toLowerCase().includes(q) ||
      (user.display_name || '').toLowerCase().includes(q) ||
      user.id.toLowerCase().includes(q)
    );
  });

  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
      <div className="flex justify-between items-end mb-8">
        <div>
          <h1 className="text-3xl font-display font-bold mb-2">User Management</h1>
          <p className="text-white/40">Manage user accounts, assign roles, and review account metadata.</p>
        </div>
        <button onClick={() => void loadUsers()} className="px-4 py-2 rounded-lg bg-white/5 border border-white/10 text-sm font-medium hover:bg-white/10 transition-colors flex items-center gap-2">
          <RefreshCw className="w-4 h-4" /> Refresh
        </button>
      </div>

      {!canEditRole && (
        <div className="mb-6 p-4 rounded-xl border border-amber-500/20 bg-amber-500/10 text-amber-300 text-sm">
          Role editing is disabled because the role column is missing in user_profiles. Add a role column to enable role-based updates.
        </div>
      )}

      {error && (
        <div className="mb-6 p-4 rounded-xl border border-red-500/20 bg-red-500/10 text-red-300 text-sm">
          {error}
        </div>
      )}

      <div className="glass-panel overflow-hidden">
        <div className="p-4 border-b border-white/5 bg-white/[0.02] flex items-center gap-3">
          <div className="flex items-center bg-white/5 rounded-lg px-3 py-1.5 border border-white/5 flex-1">
            <Search className="w-4 h-4 text-white/30 mr-2" />
            <input
              type="text"
              placeholder="Search by email, name or user id"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="bg-transparent border-none outline-none text-sm w-full text-white placeholder:text-white/30"
            />
          </div>
        </div>

        <div className="grid grid-cols-[2fr_1.5fr_1fr_1fr_1fr] gap-3 p-4 border-b border-white/10 text-xs font-semibold text-white/40 uppercase tracking-wider bg-black/20">
          <div>Email</div>
          <div>Name</div>
          <div>Role</div>
          <div>Created</div>
          <div>User ID</div>
        </div>

        {loading ? (
          <div className="p-8 text-center text-white/40">Loading users...</div>
        ) : filteredUsers.length === 0 ? (
          <div className="p-8 text-center text-white/30">No users found.</div>
        ) : (
          filteredUsers.map((user) => (
            <div key={user.id} className="grid grid-cols-[2fr_1.5fr_1fr_1fr_1fr] gap-3 p-4 border-b border-white/5 items-center hover:bg-white/[0.02] transition-colors">
              <div className="font-mono text-sm text-white/80 truncate pr-2">{user.email}</div>
              <div className="text-sm text-white/70 truncate pr-2">{user.display_name || 'Not set'}</div>
              <div>
                <select
                  disabled={!canEditRole || savingUserId === user.id}
                  value={user.role}
                  onChange={(e) => void handleRoleChange(user.id, e.target.value as UserRole)}
                  className="bg-white/5 border border-white/10 text-sm text-white rounded-lg px-2 py-1 outline-none disabled:opacity-50"
                >
                  <option value="user">user</option>
                  <option value="admin">admin</option>
                </select>
              </div>
              <div className="font-mono text-xs text-white/50">{user.created_at ? new Date(user.created_at).toLocaleDateString() : '—'}</div>
              <div className="font-mono text-xs text-emerald-300 truncate">{user.id}</div>
            </div>
          ))
        )}
      </div>
    </motion.div>
  );
}

function useLiveThreats() {
  const [threats, setThreats] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchThreats() {
      const { data } = await supabase.from('scan_logs').select('*').order('created_at', { ascending: false }).limit(200);
      if (data) {
        const mapped = data.map((row: any) => ({
          id: String(row.id || '').substring(0, 8),
          time: new Date(row.created_at).toLocaleTimeString() + ' - ' + new Date(row.created_at).toLocaleDateString(),
          url: String(row.url || '').replace(/^https?:\/\//, ''),
          type: row.model_used || 'Phishing',
          confidence: ((row.confidence || 0) * 100).toFixed(1) + '%',
          action: row.action_taken || (row.status === 'danger' ? 'Blocked' : 'Warned'),
          ip: 'Anonymous',
          country: 'Global',
          endpoint_id: row.endpoint_id || 'Unlinked endpoint',
          user_id: row.user_id || 'Unlinked user',
        }));
        setThreats(mapped);
      }
      setLoading(false);
    }
    fetchThreats();
    const interval = setInterval(fetchThreats, 5000); // Live poll every 5s
    return () => clearInterval(interval);
  }, []);

  return { threats, loading };
}

function ThreatIntelView() {
  const { threats: allThreats, loading } = useLiveThreats();
  const [filterType, setFilterType] = useState<string>('all');
  const [filterAction, setFilterAction] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [selected, setSelected] = useState<string | null>(null);

  const filtered = useMemo(() => allThreats.filter(t => {
    if (filterAction !== 'all' && t.action !== filterAction) return false;
    if (
      searchQuery &&
      !t.url.toLowerCase().includes(searchQuery.toLowerCase()) &&
      !t.id.toLowerCase().includes(searchQuery.toLowerCase()) &&
      !t.endpoint_id.toLowerCase().includes(searchQuery.toLowerCase()) &&
      !t.user_id.toLowerCase().includes(searchQuery.toLowerCase())
    ) return false;
    return true;
  }), [allThreats, filterType, filterAction, searchQuery]);

  const selectedThreat = selected ? allThreats.find(t => t.id === selected) : null;

  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
      <div className="flex justify-between items-end mb-8">
        <div>
          <h1 className="text-3xl font-display font-bold mb-2 flex items-center gap-3">
            Threat Intelligence
            {loading ? (
              <span className="flex items-center text-xs font-mono text-indigo-400 bg-indigo-500/10 px-2 py-1 rounded-full border border-indigo-500/20">
                <RefreshCw className="w-3 h-3 mr-1 animate-spin" /> Fetching Live DB...
              </span>
            ) : (
              <span className="flex items-center text-xs font-mono text-emerald-400 bg-emerald-500/10 px-2 py-1 rounded-full border border-emerald-500/20">
                <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse mr-2" /> Live Database Connected
              </span>
            )}
          </h1>
          <p className="text-white/40">Live stream of blocked and flagged phishing attempts across all anonymous endpoints globally.</p>
        </div>
        <button className="px-4 py-2 rounded-lg bg-emerald-500 text-black text-sm font-semibold hover:bg-emerald-400 transition-colors">Export Threats</button>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-4 gap-4 mb-8">
        {[
          { label: 'Total Threats Mapped', value: allThreats.length, color: 'text-white' },
          { label: 'Phishing Vectors', value: allThreats.filter(t => t.action === 'Blocked' || t.action === 'Warned').length, color: 'text-red-400' },
          { label: 'Endpoints Tracking', value: new Set(allThreats.map(t => t.endpoint_id)).size, color: 'text-amber-400' },
          { label: 'Users Impacted', value: new Set(allThreats.map(t => t.user_id).filter((id) => id !== 'Unlinked user')).size, color: 'text-cyan-400' },
          { label: 'Total Blocked', value: allThreats.filter(t => t.action === 'Blocked').length, color: 'text-emerald-400' },
        ].map(card => (
          <div key={card.label} className="glass-panel p-5">
            <div className={`text-2xl font-bold font-mono ${card.color} mb-1`}>{card.value}</div>
            <div className="text-sm text-white/40">{card.label}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Threat Table */}
        <div className="lg:col-span-2 glass-panel overflow-hidden">
          <div className="p-4 border-b border-white/5 flex gap-3 items-center bg-white/[0.02]">
            <div className="flex items-center bg-white/5 rounded-lg px-3 py-1.5 border border-white/5 flex-1">
              <Search className="w-4 h-4 text-white/30 mr-2" />
              <input type="text" placeholder="Search targets or endpoints..." value={searchQuery} onChange={e => setSearchQuery(e.target.value)}
                className="bg-transparent border-none outline-none text-sm w-full text-white placeholder:text-white/30" />
            </div>
            <select value={filterAction} onChange={e => setFilterAction(e.target.value)}
              className="bg-white/5 border border-white/10 text-sm text-white rounded-lg px-3 py-1.5 outline-none">
              <option value="all">All Actions</option>
              <option value="Blocked">Blocked</option>
              <option value="Warned">Warned</option>
              <option value="Passed">Passed</option>
            </select>
          </div>
          <div className="grid grid-cols-[1fr_2fr_1fr_1fr_1fr_auto] gap-3 p-4 border-b border-white/10 text-xs font-semibold text-white/40 uppercase tracking-wider bg-black/20">
            <div>Log ID</div><div>Target URL</div><div>User</div><div>Endpoint</div><div>Confidence</div><div>Action</div>
          </div>
          {filtered.length === 0 ? (
            <div className="p-8 text-center text-white/30 text-sm">No live data found in Supabase. Scan a malicious URL using the extension!</div>
          ) : (
            filtered.map((threat, i) => (
              <motion.div key={threat.id} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.04 }}
                onClick={() => setSelected(threat.id === selected ? null : threat.id)}
                className={`grid grid-cols-[1fr_2fr_1fr_1fr_1fr_auto] gap-3 p-4 border-b border-white/5 cursor-pointer transition-colors items-center ${
                  selected === threat.id ? 'bg-emerald-500/[0.05] border-l-2 border-l-emerald-500' : 'hover:bg-white/[0.03]'
                }`}>
                <div className="font-mono text-xs text-white/50">{threat.id}</div>
                <div className="font-mono text-sm text-white truncate pr-4">{threat.url}</div>
                <div className="font-mono text-xs text-cyan-300 truncate pr-1">{threat.user_id}</div>
                <div className="font-mono text-xs text-blue-400">{threat.endpoint_id}</div>
                <div className="font-mono text-sm text-emerald-400">{threat.confidence}</div>
                <div><span className={`text-xs font-medium flex items-center gap-1 ${
                  threat.action === 'Blocked' ? 'text-red-400' : threat.action === 'Warned' ? 'text-amber-400' : 'text-emerald-400'
                }`}>{threat.action === 'Blocked' ? <ShieldAlert className="w-3 h-3" /> : threat.action === 'Warned' ? <AlertTriangle className="w-3 h-3" /> : <CheckCircle2 className="w-3 h-3" />}{threat.action}</span></div>
              </motion.div>
            ))
          )}
        </div>

        {/* Threat Detail Panel */}
        <div className="glass-panel p-6">
          {selectedThreat ? (
            <>
              <h3 className="font-display font-semibold mb-4 flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-red-400" /> Live Threat Detail
              </h3>
              <div className="space-y-3">
                {[['Log ID', selectedThreat.id], ['Time', selectedThreat.time], ['Target URL', selectedThreat.url], ['Model Version', selectedThreat.type], ['ML Confidence', selectedThreat.confidence], ['Action Taken', selectedThreat.action], ['User ID', selectedThreat.user_id], ['Origin Endpoint', selectedThreat.endpoint_id], ['Privacy Status', 'Anonymous Tracking']].map(([k, v]) => (
                  <div key={k} className="flex justify-between py-2 border-b border-white/5">
                    <span className="text-sm text-white/40">{k}</span>
                    <span className="text-sm font-mono text-white text-right max-w-[60%] break-all">{v}</span>
                  </div>
                ))}
              </div>
              <div className="mt-6 space-y-2">
                <button className="w-full py-2 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-sm hover:bg-red-500/20 transition-colors">Blacklist Domain Globally</button>
                <button className="w-full py-2 rounded-lg bg-white/5 border border-white/10 text-white/60 text-sm hover:bg-white/10 transition-colors">Add to Safe Whitelist</button>
              </div>
            </>
          ) : (
            <div className="h-full flex flex-col items-center justify-center text-white/20 text-sm">
              <ShieldAlert className="w-10 h-10 mb-3 opacity-30" />
              <p>Click a row to see live Supabase details</p>
            </div>
          )}
        </div>
      </div>
    </motion.div>
  );
}

interface ModelHealth {
  online: boolean;
  latencyMs: number;
  sampleInferenceMs: number;
  endpoint: string;
  model: string;
}

function MLModelsView() {
  const [health, setHealth] = useState<ModelHealth | null>(null);
  const [loading, setLoading] = useState(true);
  const [lastChecked, setLastChecked] = useState<string>('');

  const checkHealth = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/health');
      const data = await res.json();
      setHealth(data.modernbert);
      setLastChecked(new Date().toLocaleTimeString());
    } catch {
      setHealth({ online: false, latencyMs: -1, sampleInferenceMs: -1, endpoint: 'https://alimusarizvi-phishing.hf.space', model: 'ModernBERT' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { checkHealth(); }, []);

  const modelStats = [
    { label: 'Architecture', value: 'ModernBERT (Transformer)' },
    { label: 'Training Data', value: 'PhishTank + DMOZ + OpenPhish' },
    { label: 'Val Accuracy', value: '98.7%' },
    { label: 'F1-Score', value: '98.4%' },
    { label: 'Precision', value: '97.9%' },
    { label: 'Recall', value: '98.9%' },
    { label: 'Hosted On', value: 'Hugging Face Spaces' },
  ];

  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
      <div className="flex justify-between items-end mb-8">
        <div>
          <h1 className="text-3xl font-display font-bold mb-2">ML Models</h1>
          <p className="text-white/40">Monitor AI model performance, health, and deployment status.</p>
        </div>
        <button onClick={checkHealth} disabled={loading}
          className="px-4 py-2 rounded-lg bg-white/5 border border-white/10 text-sm font-medium hover:bg-white/10 transition-colors flex items-center gap-2 disabled:opacity-50">
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Refresh Status
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        {/* ModernBERT Status Card */}
        <div className="lg:col-span-2 glass-panel p-6">
          <div className="flex items-start justify-between mb-6">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-emerald-500/10 border border-emerald-500/20 rounded-xl flex items-center justify-center">
                <Cpu className="w-5 h-5 text-emerald-400" />
              </div>
              <div>
                <h2 className="font-display font-semibold text-lg">ModernBERT Phishing Detector</h2>
                <p className="text-sm text-white/40 font-mono">{health?.endpoint || 'alimusarizvi-phishing.hf.space'}</p>
              </div>
            </div>
            <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-sm font-medium border ${
              loading ? 'bg-indigo-500/10 text-indigo-400 border-indigo-500/20' :
              health?.online ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' :
              'bg-red-500/10 text-red-400 border-red-500/20'
            }`}>
              <div className={`w-2 h-2 rounded-full ${
                loading ? 'bg-indigo-400 animate-pulse' :
                health?.online ? 'bg-emerald-400 animate-pulse' : 'bg-red-400'
              }`} />
              {loading ? 'Checking…' : health?.online ? 'Online' : 'Offline'}
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4 mb-6">
            <div className="bg-white/[0.03] border border-white/5 rounded-xl p-4">
              <div className="text-xs text-white/40 mb-1">API Latency</div>
              <div className="text-2xl font-mono font-bold">
                {loading ? '—' : health?.latencyMs && health.latencyMs > 0 ? `${health.latencyMs}ms` : 'N/A'}
              </div>
            </div>
            <div className="bg-white/[0.03] border border-white/5 rounded-xl p-4">
              <div className="text-xs text-white/40 mb-1">Inference Time</div>
              <div className="text-2xl font-mono font-bold">
                {loading ? '—' : health?.sampleInferenceMs && health.sampleInferenceMs > 0 ? `${health.sampleInferenceMs.toFixed(0)}ms` : 'N/A'}
              </div>
            </div>
          </div>

          <div className="space-y-2">
            {modelStats.map(({ label, value }) => (
              <div key={label} className="flex justify-between py-2 border-b border-white/5">
                <span className="text-sm text-white/40">{label}</span>
                <span className="text-sm font-medium text-white">{value}</span>
              </div>
            ))}
          </div>
          {lastChecked && <p className="text-xs text-white/20 mt-4">Last checked: {lastChecked}</p>}
        </div>

        {/* Performance Chart */}
        <div className="glass-panel p-6 flex flex-col">
          <h3 className="font-display font-semibold mb-4">Accuracy History</h3>
          <div className="flex-1">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={[
                { version: 'v1.0', accuracy: 94.2 }, { version: 'v1.1', accuracy: 95.8 },
                { version: 'v1.2', accuracy: 96.5 }, { version: 'v2.0', accuracy: 97.2 },
                { version: 'v2.1', accuracy: 97.9 }, { version: 'v2.4', accuracy: 98.7 },
              ]} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorAcc" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#10b981" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#10b981" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#ffffff10" vertical={false} />
                <XAxis dataKey="version" stroke="#ffffff40" fontSize={10} tickLine={false} axisLine={false} />
                <YAxis stroke="#ffffff40" fontSize={10} tickLine={false} axisLine={false} domain={[90, 100]} />
                <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px', color: '#fff' }} />
                <Area type="monotone" dataKey="accuracy" stroke="#10b981" strokeWidth={2} fillOpacity={1} fill="url(#colorAcc)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          <a href="https://alimusarizvi-phishing.hf.space/docs" target="_blank" rel="noopener noreferrer"
            className="mt-4 w-full py-2 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-sm font-medium hover:bg-emerald-500/20 transition-colors text-center block">
            View API Docs →
          </a>
        </div>
      </div>
    </motion.div>
  );
}

function NetworkMapView() {
  const nodes = [
    { id: 'HQ', x: 50, y: 50, label: 'HQ Network', color: '#10b981', size: 16, endpoints: 1420 },
    { id: 'BR1', x: 20, y: 25, label: 'Branch NY', color: '#10b981', size: 12, endpoints: 340 },
    { id: 'BR2', x: 75, y: 30, label: 'Branch LA', color: '#10b981', size: 12, endpoints: 280 },
    { id: 'BR3', x: 25, y: 75, label: 'Branch CHI', color: '#f59e0b', size: 10, endpoints: 180 },
    { id: 'BR4', x: 80, y: 70, label: 'Branch MIA', color: '#ef4444', size: 10, endpoints: 95 },
    { id: 'SRV', x: 50, y: 15, label: 'Cloud API', color: '#6366f1', size: 10, endpoints: 0 },
  ];
  const edges = [
    ['HQ','BR1'],['HQ','BR2'],['HQ','BR3'],['HQ','BR4'],['HQ','SRV'],
    ['BR1','SRV'],['BR2','SRV'],
  ];

  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
      <div className="flex justify-between items-end mb-8">
        <div>
          <h1 className="text-3xl font-display font-bold mb-2">Network Map</h1>
          <p className="text-white/40">Visual overview of protected network segments and their security state.</p>
        </div>
      </div>
      <div className="glass-panel p-6">
        <div className="relative w-full" style={{ paddingBottom: '50%' }}>
          <svg className="absolute inset-0 w-full h-full" viewBox="0 0 100 55">
            {edges.map(([from, to]) => {
              const n1 = nodes.find(n => n.id === from)!;
              const n2 = nodes.find(n => n.id === to)!;
              return <line key={`${from}-${to}`} x1={n1.x} y1={n1.y} x2={n2.x} y2={n2.y} stroke="rgba(255,255,255,0.1)" strokeWidth="0.3" strokeDasharray="1 1" />;
            })}
            {nodes.map(node => (
              <g key={node.id}>
                <circle cx={node.x} cy={node.y} r={node.size / 6} fill={node.color} opacity={0.15} />
                <circle cx={node.x} cy={node.y} r={node.size / 9} fill={node.color} />
                <text x={node.x} y={node.y + node.size / 6 + 2.5} textAnchor="middle" fontSize={2.5} fill="rgba(255,255,255,0.6)" fontFamily="monospace">{node.label}</text>
                {node.endpoints > 0 && <text x={node.x} y={node.y + node.size / 6 + 5} textAnchor="middle" fontSize={2} fill="rgba(255,255,255,0.3)">{node.endpoints} endpoints</text>}
              </g>
            ))}
          </svg>
        </div>
        <div className="flex items-center gap-6 mt-4 text-xs text-white/40">
          {[{ color: '#10b981', label: 'Secure' }, { color: '#f59e0b', label: 'Warning' }, { color: '#ef4444', label: 'At Risk' }, { color: '#6366f1', label: 'Cloud Service' }].map(({ color, label }) => (
            <span key={label} className="flex items-center gap-1.5"><div className="w-2.5 h-2.5 rounded-full" style={{ background: color }} />{label}</span>
          ))}
        </div>
      </div>
    </motion.div>
  );
}

function DataLogsView() {
  const { threats: liveLogs, loading } = useLiveThreats();
  const [levelFilter, setLevelFilter] = useState<string>('all');
  const [logSearch, setLogSearch] = useState('');

  const filteredLogs = useMemo(() => liveLogs.filter(l => {
    // Map action to level for filtering
    const level = l.action === 'Blocked' ? 'danger' : l.action === 'Warned' ? 'warning' : 'info';
    if (levelFilter !== 'all' && level !== levelFilter) return false;
    if (
      logSearch &&
      !l.url.toLowerCase().includes(logSearch.toLowerCase()) &&
      !l.endpoint_id.toLowerCase().includes(logSearch.toLowerCase()) &&
      !l.user_id.toLowerCase().includes(logSearch.toLowerCase())
    ) return false;
    return true;
  }), [liveLogs, levelFilter, logSearch]);

  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
      <div className="flex justify-between items-end mb-8">
        <div>
          <h1 className="text-3xl font-display font-bold mb-2 flex items-center gap-3">
            Data Logs 
            {loading && <RefreshCw className="w-4 h-4 text-white/40 animate-spin" />}
          </h1>
          <p className="text-white/40">Complete global audit trail fetched live from Supabase.</p>
        </div>
        <button className="px-4 py-2 rounded-lg bg-emerald-500 text-black text-sm font-semibold hover:bg-emerald-400 transition-colors">Export DB Logs</button>
      </div>
      <div className="glass-panel overflow-hidden">
        <div className="p-4 border-b border-white/5 flex items-center gap-3 bg-white/[0.02]">
          <div className="flex items-center bg-white/5 rounded-lg px-3 py-1.5 border border-white/5 flex-1">
            <Search className="w-4 h-4 text-white/30 mr-2" />
            <input type="text" placeholder="Filter logs by url or endpoint..." value={logSearch} onChange={e => setLogSearch(e.target.value)}
              className="bg-transparent border-none outline-none text-sm w-full text-white placeholder:text-white/30" />
          </div>
          <select value={levelFilter} onChange={e => setLevelFilter(e.target.value)}
            className="bg-white/5 border border-white/10 text-sm text-white rounded-lg px-3 py-1.5 outline-none">
            <option value="all">All Levels</option>
            <option value="danger">Danger</option>
            <option value="warning">Warning</option>
            <option value="info">Info</option>
          </select>
        </div>
        <div className="grid grid-cols-[100px_160px_2fr_1fr_1fr_1fr] gap-4 p-4 border-b border-white/10 text-xs font-semibold text-white/40 uppercase tracking-wider bg-black/20">
          <div>Log ID</div><div>Timestamp</div><div>Target URL</div><div>User</div><div>Endpoint</div><div>Confidence</div>
        </div>
        
        {filteredLogs.length === 0 ? (
          <div className="p-8 text-center text-white/30 text-sm">No live logs available. Waiting for endpoint scans...</div>
        ) : (
          filteredLogs.map((log, i) => {
            const level = log.action === 'Blocked' ? 'danger' : log.action === 'Warned' ? 'warning' : 'info';
            return (
              <motion.div key={log.id} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.03 }}
                className="grid grid-cols-[100px_160px_2fr_1fr_1fr_1fr] gap-4 p-4 border-b border-white/5 hover:bg-white/[0.02] transition-colors items-center">
                <div className="font-mono text-xs text-white/40">{log.id}</div>
                <div className="font-mono text-xs text-white/50">{log.time}</div>
                <div className="flex items-center gap-2">
                  {level === 'danger' && <ShieldAlert className="w-3.5 h-3.5 text-red-400 shrink-0" />}
                  {level === 'warning' && <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0" />}
                  {level === 'info' && <Info className="w-3.5 h-3.5 text-blue-400 shrink-0" />}
                  <span className="text-sm text-white/80 truncate">Scan: {log.url} - {log.action}</span>
                </div>
                <div className="font-mono text-xs text-cyan-300 truncate">{log.user_id}</div>
                <div className="font-mono text-sm text-emerald-400">{log.endpoint_id}</div>
                <div className="font-mono text-sm text-emerald-400">{log.confidence}</div>
              </motion.div>
            );
          })
        )}
      </div>
    </motion.div>
  );
}

function SettingsView() {
  const [apiUrl, setApiUrl] = useState('https://alimusarizvi-phishing.hf.space');
  const [vercelUrl, setVercelUrl] = useState('https://your-app.vercel.app');
  const [blockThreshold, setBlockThreshold] = useState(85);
  const [warnThreshold, setWarnThreshold] = useState(60);
  const [saved, setSaved] = useState(false);

  const handleSave = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
      <div className="mb-8">
        <h1 className="text-3xl font-display font-bold mb-2">Settings</h1>
        <p className="text-white/40">Configure API endpoints, detection thresholds, and deployment.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* API Configuration */}
        <div className="glass-panel p-6">
          <h2 className="font-display font-semibold mb-6 flex items-center gap-2">
            <Server className="w-4 h-4 text-emerald-400" /> API Configuration
          </h2>
          <div className="space-y-5">
            <div>
              <label className="block text-sm text-white/60 mb-2">ModernBERT HF Space URL</label>
              <input type="text" value={apiUrl} onChange={e => setApiUrl(e.target.value)}
                className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2.5 text-sm font-mono text-white outline-none focus:border-emerald-500/50 transition-colors" />
            </div>
            <div>
              <label className="block text-sm text-white/60 mb-2">Vercel App URL</label>
              <input type="text" value={vercelUrl} onChange={e => setVercelUrl(e.target.value)}
                className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-2.5 text-sm font-mono text-white outline-none focus:border-emerald-500/50 transition-colors" />
            </div>
          </div>
        </div>

        {/* Detection Thresholds */}
        <div className="glass-panel p-6">
          <h2 className="font-display font-semibold mb-6 flex items-center gap-2">
            <Filter className="w-4 h-4 text-amber-400" /> Detection Thresholds
          </h2>
          <div className="space-y-5">
            <div>
              <div className="flex justify-between mb-2">
                <label className="text-sm text-white/60">Block Threshold (Phishing Probability)</label>
                <span className="text-sm font-mono text-red-400">{blockThreshold}%</span>
              </div>
              <input type="range" min={50} max={99} value={blockThreshold} onChange={e => setBlockThreshold(Number(e.target.value))}
                className="w-full accent-red-400" />
            </div>
            <div>
              <div className="flex justify-between mb-2">
                <label className="text-sm text-white/60">Warn Threshold (Phishing Probability)</label>
                <span className="text-sm font-mono text-amber-400">{warnThreshold}%</span>
              </div>
              <input type="range" min={20} max={blockThreshold - 5} value={warnThreshold} onChange={e => setWarnThreshold(Number(e.target.value))}
                className="w-full accent-amber-400" />
            </div>
          </div>
        </div>

        {/* Extension Download */}
        <div className="glass-panel p-6">
          <h2 className="font-display font-semibold mb-6 flex items-center gap-2">
            <Globe className="w-4 h-4 text-blue-400" /> Extension Deployment
          </h2>
          <p className="text-sm text-white/50 mb-4 leading-relaxed">
            After building with <span className="font-mono bg-white/5 px-1.5 py-0.5 rounded text-white">npm run build:extension</span>, load the <span className="font-mono bg-white/5 px-1.5 py-0.5 rounded text-white">extension/dist/</span> folder in Chrome.
          </p>
          <div className="space-y-3">
            <div className="flex items-start gap-3 p-3 bg-white/[0.03] rounded-lg border border-white/5">
              <div className="w-6 h-6 rounded-full bg-emerald-500/20 text-emerald-400 flex items-center justify-center text-xs font-bold shrink-0 mt-0.5">1</div>
              <p className="text-sm text-white/60">Open Chrome → <code className="text-white">chrome://extensions</code></p>
            </div>
            <div className="flex items-start gap-3 p-3 bg-white/[0.03] rounded-lg border border-white/5">
              <div className="w-6 h-6 rounded-full bg-emerald-500/20 text-emerald-400 flex items-center justify-center text-xs font-bold shrink-0 mt-0.5">2</div>
              <p className="text-sm text-white/60">Enable <strong className="text-white">Developer Mode</strong> (top right toggle)</p>
            </div>
            <div className="flex items-start gap-3 p-3 bg-white/[0.03] rounded-lg border border-white/5">
              <div className="w-6 h-6 rounded-full bg-emerald-500/20 text-emerald-400 flex items-center justify-center text-xs font-bold shrink-0 mt-0.5">3</div>
              <p className="text-sm text-white/60">Click <strong className="text-white">Load unpacked</strong> → select <code className="text-white">extension/dist/</code></p>
            </div>
          </div>
        </div>

        {/* Save */}
        <div className="glass-panel p-6 flex flex-col justify-between">
          <div>
            <h2 className="font-display font-semibold mb-4 flex items-center gap-2">
              <Database className="w-4 h-4 text-indigo-400" /> About SafeBrowse
            </h2>
            <div className="space-y-2">
              {[['Version', '1.0.0'], ['ML Model', 'ModernBERT (HF Space)'], ['Built With', 'React + Vite + Vercel'], ['Extension', 'Chrome MV3']].map(([k, v]) => (
                <div key={k} className="flex justify-between py-1.5 border-b border-white/5">
                  <span className="text-sm text-white/40">{k}</span>
                  <span className="text-sm font-mono text-white">{v}</span>
                </div>
              ))}
            </div>
          </div>
          <button onClick={handleSave}
            className={`mt-6 w-full py-2.5 rounded-lg text-sm font-semibold transition-all ${
              saved ? 'bg-emerald-500 text-black' : 'bg-white/10 border border-white/15 text-white hover:bg-white/15'
            }`}>
            {saved ? '✓ Settings Saved' : 'Save Settings'}
          </button>
        </div>
      </div>
    </motion.div>
  );
}

// --- Sub-Views ---

function OverviewView() {
  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
      <div className="flex justify-between items-end mb-8">
        <div>
          <h1 className="text-3xl font-display font-bold mb-2">Security Overview</h1>
          <p className="text-white/40">Real-time telemetry from 12,450 active endpoints.</p>
        </div>
        <div className="flex gap-2">
          <button className="px-4 py-2 rounded-lg bg-white/5 border border-white/10 text-sm font-medium hover:bg-white/10 transition-colors">Last 24 Hours</button>
          <button className="px-4 py-2 rounded-lg bg-emerald-500 text-black text-sm font-semibold hover:bg-emerald-400 transition-colors">Export Report</button>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <StatCard title="Total Scans (24h)" value="2.4M" trend="+12.5%" trendUp={true} icon={<Globe className="w-5 h-5 text-blue-400" />} />
        <StatCard title="Threats Blocked" value="14,205" trend="+5.2%" trendUp={true} icon={<ShieldAlert className="w-5 h-5 text-red-400" />} alert />
        <StatCard title="ML Confidence Avg" value="98.7%" trend="+0.3%" trendUp={true} icon={<Cpu className="w-5 h-5 text-emerald-400" />} />
        <StatCard title="Active Endpoints" value="12,450" trend="-2.1%" trendUp={false} icon={<Users className="w-5 h-5 text-amber-400" />} />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        <div className="lg:col-span-2 glass-panel p-6">
          <div className="flex justify-between items-center mb-6">
            <h2 className="text-lg font-display font-semibold">Threat Detection Volume</h2>
            <div className="flex gap-4 text-sm font-mono text-white/40">
              <span className="flex items-center gap-2"><div className="w-2 h-2 rounded-full bg-red-500"></div> Phishing</span>
              <span className="flex items-center gap-2"><div className="w-2 h-2 rounded-full bg-amber-500"></div> Malware</span>
            </div>
          </div>
          <div className="h-[300px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={threatData} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorPhishing" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="colorMalware" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#f59e0b" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#ffffff10" vertical={false} />
                <XAxis dataKey="time" stroke="#ffffff40" fontSize={12} tickLine={false} axisLine={false} />
                <YAxis stroke="#ffffff40" fontSize={12} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px', color: '#fff' }} itemStyle={{ color: '#fff' }} />
                <Area type="monotone" dataKey="phishing" stroke="#ef4444" strokeWidth={2} fillOpacity={1} fill="url(#colorPhishing)" />
                <Area type="monotone" dataKey="malware" stroke="#f59e0b" strokeWidth={2} fillOpacity={1} fill="url(#colorMalware)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="glass-panel p-6 flex flex-col">
          <h2 className="text-lg font-display font-semibold mb-6">Threat Categories</h2>
          <div className="flex-1">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={[
                { name: 'Typosquatting', value: 4000 },
                { name: 'Credential', value: 3000 },
                { name: 'Malware', value: 2000 },
                { name: 'Insecure Form', value: 2780 },
              ]} layout="vertical" margin={{ top: 0, right: 0, left: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#ffffff10" horizontal={true} vertical={false} />
                <XAxis type="number" hide />
                <YAxis dataKey="name" type="category" stroke="#ffffff40" fontSize={12} tickLine={false} axisLine={false} width={100} />
                <Tooltip cursor={{fill: '#ffffff05'}} contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px' }} />
                <Bar dataKey="value" fill="#10b981" radius={[0, 4, 4, 0]} barSize={24} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Data Table */}
      <div className="glass-panel overflow-hidden">
        <div className="p-6 border-b border-white/5 flex justify-between items-center bg-white/[0.02]">
          <h2 className="text-lg font-display font-semibold">Recent Interceptions</h2>
          <button className="text-sm text-emerald-400 hover:text-emerald-300 font-medium transition-colors">View All Logs &rarr;</button>
        </div>
        
        <div className="grid grid-cols-[120px_2fr_1fr_1fr_auto] gap-4 p-4 border-b border-white/10 text-xs font-semibold text-white/40 uppercase tracking-wider bg-black/20">
          <div>Timestamp</div>
          <div>Target URL</div>
          <div>Threat Type</div>
          <div>ML Confidence</div>
          <div className="text-right">Action Taken</div>
        </div>
        
        <div className="flex flex-col">
          {recentThreats.map((threat, i) => (
            <motion.div key={threat.id} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }} className="data-row items-center">
              <div className="font-mono text-sm text-white/60">{threat.time}</div>
              <div className="font-mono text-sm text-white truncate pr-4">{threat.url}</div>
              <div>
                <span className={`inline-flex items-center px-2 py-1 rounded-md text-xs font-medium border ${
                  threat.type === 'Phishing' ? 'bg-red-500/10 text-red-400 border-red-500/20' :
                  threat.type === 'Typosquatting' ? 'bg-amber-500/10 text-amber-400 border-amber-500/20' :
                  'bg-blue-500/10 text-blue-400 border-blue-500/20'
                }`}>
                  {threat.type}
                </span>
              </div>
              <div className="font-mono text-sm text-emerald-400">{threat.confidence}</div>
              <div className="text-right">
                <span className={`inline-flex items-center gap-1.5 text-sm font-medium ${
                  threat.action === 'Blocked' ? 'text-red-400' : 'text-amber-400'
                }`}>
                  {threat.action === 'Blocked' ? <ShieldAlert className="w-4 h-4" /> : <AlertTriangle className="w-4 h-4" />}
                  {threat.action}
                </span>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </motion.div>
  );
}

function EndpointsView({ searchQuery }: { searchQuery: string }) {
  const [selectedEndpoints, setSelectedEndpoints] = useState<string[]>([]);
  const [endpoints, setEndpoints] = useState(endpointsData);
  const navigate = useNavigate();

  const filteredEndpoints = useMemo(() => {
    if (!searchQuery) return endpoints;
    const lowerQuery = searchQuery.toLowerCase();
    return endpoints.filter(ep => 
      ep.hostname.toLowerCase().includes(lowerQuery) ||
      ep.ip.toLowerCase().includes(lowerQuery) ||
      ep.os.toLowerCase().includes(lowerQuery) ||
      ep.id.toLowerCase().includes(lowerQuery)
    );
  }, [endpoints, searchQuery]);

  const handleSelectAll = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.checked) {
      setSelectedEndpoints(filteredEndpoints.map(ep => ep.id));
    } else {
      setSelectedEndpoints([]);
    }
  };

  const handleSelect = (id: string) => {
    setSelectedEndpoints(prev => 
      prev.includes(id) ? prev.filter(epId => epId !== id) : [...prev, id]
    );
  };

  const handleIsolate = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setEndpoints(endpoints.map(ep => 
      ep.id === id ? { ...ep, status: 'Isolated', risk: 'High' } : ep
    ));
  };

  const handleRowClick = (id: string) => {
    navigate(`/endpoint/${id}`);
  };

  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
      <div className="flex justify-between items-end mb-8">
        <div>
          <h1 className="text-3xl font-display font-bold mb-2">Endpoint Management</h1>
          <p className="text-white/40">Monitor and manage 12,450 active devices across your network.</p>
        </div>
        <div className="flex gap-2">
          <button className="px-4 py-2 rounded-lg bg-white/5 border border-white/10 text-sm font-medium hover:bg-white/10 transition-colors flex items-center gap-2">
            <RefreshCw className="w-4 h-4" /> Sync Policies
          </button>
          <button className="px-4 py-2 rounded-lg bg-emerald-500 text-black text-sm font-semibold hover:bg-emerald-400 transition-colors">
            Deploy Agent
          </button>
        </div>
      </div>

      {/* Endpoint Activity Heatmap */}
      <div className="glass-panel p-6 mb-8">
        <div className="flex justify-between items-center mb-6">
          <h2 className="text-lg font-display font-semibold">Endpoint Activity Heatmap (24h)</h2>
          <div className="flex gap-4 text-sm font-mono text-white/40">
            <span className="flex items-center gap-2"><div className="w-3 h-3 rounded-sm bg-emerald-500/20"></div> Low</span>
            <span className="flex items-center gap-2"><div className="w-3 h-3 rounded-sm bg-amber-500/50"></div> Medium</span>
            <span className="flex items-center gap-2"><div className="w-3 h-3 rounded-sm bg-red-500/80"></div> High</span>
          </div>
        </div>
        <div className="h-32 flex flex-col gap-1">
          {/* Mock Heatmap Grid */}
          {Array.from({ length: 5 }).map((_, rowIndex) => (
            <div key={rowIndex} className="flex gap-1 flex-1">
              {Array.from({ length: 24 }).map((_, colIndex) => {
                // Generate random activity level for mock data
                const activityLevel = Math.random();
                let bgColor = 'bg-white/5'; // Default low
                if (activityLevel > 0.8) bgColor = 'bg-red-500/80';
                else if (activityLevel > 0.5) bgColor = 'bg-amber-500/50';
                else if (activityLevel > 0.2) bgColor = 'bg-emerald-500/20';

                return (
                  <div 
                    key={colIndex} 
                    className={`flex-1 rounded-sm ${bgColor} hover:opacity-80 transition-opacity cursor-pointer`}
                    title={`Hour ${colIndex}:00 - Activity Level`}
                  ></div>
                );
              })}
            </div>
          ))}
        </div>
      </div>

      {/* Bulk Actions Bar */}
      <AnimatePresence>
        {selectedEndpoints.length > 0 && (
          <motion.div 
            initial={{ opacity: 0, height: 0, marginBottom: 0 }}
            animate={{ opacity: 1, height: 'auto', marginBottom: 16 }}
            exit={{ opacity: 0, height: 0, marginBottom: 0 }}
            className="glass-panel p-3 flex items-center justify-between bg-emerald-500/5 border-emerald-500/20 overflow-hidden"
          >
            <div className="flex items-center gap-3 pl-2">
              <span className="flex items-center justify-center w-6 h-6 rounded-full bg-emerald-500/20 text-emerald-400 text-xs font-bold">
                {selectedEndpoints.length}
              </span>
              <span className="text-sm font-medium text-emerald-400">Endpoints Selected</span>
            </div>
            <div className="flex gap-2">
              <button className="px-3 py-1.5 rounded bg-white/5 border border-white/10 text-xs font-medium hover:bg-white/10 transition-colors">
                Deploy Agent to Selected
              </button>
              <button className="px-3 py-1.5 rounded bg-red-500/10 border border-red-500/20 text-red-400 text-xs font-medium hover:bg-red-500/20 transition-colors flex items-center gap-1.5">
                <Power className="w-3 h-3" /> Isolate Selected
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Endpoints Table */}
      <div className="glass-panel overflow-hidden">
        <div className="p-4 border-b border-white/5 flex justify-between items-center bg-white/[0.02]">
          <div className="flex gap-2">
            <select className="bg-white/5 border border-white/10 text-sm text-white rounded-lg px-3 py-1.5 outline-none focus:border-emerald-500">
              <option>All Operating Systems</option>
              <option>Windows</option>
              <option>macOS</option>
              <option>Linux</option>
            </select>
            <select className="bg-white/5 border border-white/10 text-sm text-white rounded-lg px-3 py-1.5 outline-none focus:border-emerald-500">
              <option>All Statuses</option>
              <option>Active</option>
              <option>Warning</option>
              <option>Offline</option>
            </select>
          </div>
          <div className="text-sm text-white/40">Showing {filteredEndpoints.length} of {endpointsData.length} endpoints</div>
        </div>
        
        <div className="grid grid-cols-[40px_100px_1.5fr_1fr_1fr_1fr_1fr_1.5fr_auto] gap-4 p-4 border-b border-white/10 text-xs font-semibold text-white/40 uppercase tracking-wider bg-black/20 items-center">
          <div>
            <input 
              type="checkbox" 
              className="rounded border-white/20 bg-white/5 text-emerald-500 focus:ring-emerald-500/50 cursor-pointer"
              checked={selectedEndpoints.length === filteredEndpoints.length && filteredEndpoints.length > 0}
              onChange={handleSelectAll}
            />
          </div>
          <div>ID</div>
          <div>Hostname</div>
          <div>IP Address</div>
          <div>OS</div>
          <div>Status</div>
          <div>Last Seen</div>
          <div>Deployment Status</div>
          <div className="text-right">Actions</div>
        </div>
        
        <div className="flex flex-col">
          {filteredEndpoints.map((ep, i) => (
            <motion.div 
              key={ep.id} 
              initial={{ opacity: 0, y: 10 }} 
              animate={{ opacity: 1, y: 0 }} 
              transition={{ delay: i * 0.05 }} 
              onClick={() => handleRowClick(ep.id)}
              className={`grid grid-cols-[40px_100px_1.5fr_1fr_1fr_1fr_1fr_1.5fr_auto] gap-4 p-4 border-b border-white/5 transition-colors items-center cursor-pointer ${
                selectedEndpoints.includes(ep.id) ? 'bg-emerald-500/[0.03]' : 'hover:bg-white/[0.04]'
              } ${ep.status === 'Isolated' ? 'border-l-2 border-l-red-500/50 opacity-70' : ''}`}
            >
              <div onClick={(e) => e.stopPropagation()}>
                <input 
                  type="checkbox" 
                  className="rounded border-white/20 bg-white/5 text-emerald-500 focus:ring-emerald-500/50 cursor-pointer"
                  checked={selectedEndpoints.includes(ep.id)}
                  onChange={() => handleSelect(ep.id)}
                />
              </div>
              <div className="font-mono text-sm text-white/60">{ep.id}</div>
              <div className="flex items-center gap-3">
                {ep.os.includes('Mac') ? <Monitor className="w-4 h-4 text-white/40" /> : <Laptop className="w-4 h-4 text-white/40" />}
                <span className="font-medium text-white">{ep.hostname}</span>
              </div>
              <div className="font-mono text-sm text-white/60">{ep.ip}</div>
              <div className="text-sm text-white/80">{ep.os}</div>
              <div>
                <span className={`inline-flex items-center gap-1.5 px-2 py-1 rounded-md text-xs font-medium border ${
                  ep.status === 'Active' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' :
                  ep.status === 'Warning' ? 'bg-amber-500/10 text-amber-400 border-amber-500/20' :
                  ep.status === 'Isolated' ? 'bg-red-500/10 text-red-400 border-red-500/20' :
                  'bg-slate-500/10 text-slate-400 border-slate-500/20'
                }`}>
                  <div className={`w-1.5 h-1.5 rounded-full ${
                    ep.status === 'Active' ? 'bg-emerald-400' :
                    ep.status === 'Warning' ? 'bg-amber-400' : 
                    ep.status === 'Isolated' ? 'bg-red-400' : 'bg-slate-400'
                  }`}></div>
                  {ep.status}
                </span>
              </div>
              <div className="font-mono text-sm text-white/40">{ep.lastSeen}</div>
              <div>
                <span className={`inline-flex items-center gap-1.5 text-xs font-medium ${
                  ep.deploymentStatus === 'Success' ? 'text-emerald-400' :
                  ep.deploymentStatus === 'Failed' ? 'text-red-400' :
                  'text-amber-400'
                }`}>
                  {ep.deploymentStatus === 'Success' && <CheckCircle2 className="w-3 h-3" />}
                  {ep.deploymentStatus === 'Failed' && <XCircle className="w-3 h-3" />}
                  {ep.deploymentStatus === 'Pending' && <RefreshCw className="w-3 h-3 animate-spin" />}
                  {ep.deploymentStatus}
                </span>
              </div>
              <div className="text-right flex items-center justify-end gap-2" onClick={(e) => e.stopPropagation()}>
                <button 
                  className={`p-1.5 rounded transition-colors ${ep.status === 'Isolated' ? 'text-white/20 cursor-not-allowed' : 'text-white/40 hover:text-white hover:bg-white/10'}`} 
                  title="Isolate Endpoint"
                  onClick={(e) => ep.status !== 'Isolated' && handleIsolate(ep.id, e)}
                  disabled={ep.status === 'Isolated'}
                >
                  <Power className="w-4 h-4" />
                </button>
                <button 
                  className={`p-1.5 rounded transition-colors ${ep.status === 'Isolated' ? 'text-white/20 cursor-not-allowed' : 'text-white/40 hover:text-white hover:bg-white/10'}`} 
                  title="More Actions"
                  disabled={ep.status === 'Isolated'}
                >
                  <MoreVertical className="w-4 h-4" />
                </button>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </motion.div>
  );
}

function EndpointDetailView() {
  const { id } = useParams();
  const navigate = useNavigate();
  const endpoint = endpointsData.find(ep => ep.id === id) || endpointsData[0];

  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="min-h-screen bg-[#050505] text-white p-8">
      <button 
        onClick={() => navigate('/')}
        className="flex items-center gap-2 text-white/60 hover:text-white transition-colors mb-8"
      >
        <ArrowLeft className="w-4 h-4" /> Back to Dashboard
      </button>

      <div className="flex justify-between items-start mb-8">
        <div>
          <h1 className="text-3xl font-display font-bold mb-2 flex items-center gap-3">
            {endpoint.hostname}
            <span className={`inline-flex items-center gap-1.5 px-2 py-1 rounded-md text-sm font-medium border ${
              endpoint.status === 'Active' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' :
              endpoint.status === 'Warning' ? 'bg-amber-500/10 text-amber-400 border-amber-500/20' :
              endpoint.status === 'Isolated' ? 'bg-red-500/10 text-red-400 border-red-500/20' :
              'bg-slate-500/10 text-slate-400 border-slate-500/20'
            }`}>
              <div className={`w-2 h-2 rounded-full ${
                endpoint.status === 'Active' ? 'bg-emerald-400' :
                endpoint.status === 'Warning' ? 'bg-amber-400' : 
                endpoint.status === 'Isolated' ? 'bg-red-400' : 'bg-slate-400'
              }`}></div>
              {endpoint.status}
            </span>
          </h1>
          <div className="flex gap-6 text-sm font-mono text-white/40">
            <span>ID: {endpoint.id}</span>
            <span>IP: {endpoint.ip}</span>
            <span>OS: {endpoint.os}</span>
          </div>
        </div>
        <div className="flex gap-2">
          <button className="px-4 py-2 rounded-lg bg-white/5 border border-white/10 text-sm font-medium hover:bg-white/10 transition-colors">
            View Full Logs
          </button>
          <button className="px-4 py-2 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-sm font-medium hover:bg-red-500/20 transition-colors flex items-center gap-2">
            <Power className="w-4 h-4" /> Isolate Endpoint
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Security Configuration */}
        <div className="glass-panel p-6">
          <h2 className="text-lg font-display font-semibold mb-6 flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-emerald-400" /> Security Configuration
          </h2>
          <div className="space-y-4">
            <div className="flex justify-between items-center py-2 border-b border-white/5">
              <span className="text-sm text-white/60">Agent Version</span>
              <span className="text-sm font-mono text-white">v2.4.1 (Up to date)</span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-white/5">
              <span className="text-sm text-white/60">Real-time Protection</span>
              <span className="text-sm font-medium text-emerald-400">Enabled</span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-white/5">
              <span className="text-sm text-white/60">Network Firewall</span>
              <span className="text-sm font-medium text-emerald-400">Strict Mode</span>
            </div>
            <div className="flex justify-between items-center py-2 border-b border-white/5">
              <span className="text-sm text-white/60">Last Full Scan</span>
              <span className="text-sm font-mono text-white">Today, 04:00 AM</span>
            </div>
          </div>
        </div>

        {/* Running Processes */}
        <div className="glass-panel p-6 lg:col-span-2">
          <h2 className="text-lg font-display font-semibold mb-6 flex items-center gap-2">
            <Terminal className="w-5 h-5 text-blue-400" /> Top Running Processes
          </h2>
          <div className="grid grid-cols-[2fr_1fr_1fr_1fr] gap-4 p-3 border-b border-white/10 text-xs font-semibold text-white/40 uppercase tracking-wider bg-black/20">
            <div>Process Name</div>
            <div>PID</div>
            <div>CPU Usage</div>
            <div>Memory</div>
          </div>
          <div className="flex flex-col">
            {[
              { name: 'chrome.exe', pid: '1420', cpu: '12.4%', mem: '1.2 GB' },
              { name: 'safebrowse-agent.exe', pid: '892', cpu: '0.5%', mem: '45 MB' },
              { name: 'svchost.exe', pid: '1104', cpu: '2.1%', mem: '120 MB' },
              { name: 'code.exe', pid: '4592', cpu: '5.8%', mem: '800 MB' },
            ].map((proc, i) => (
              <div key={i} className="grid grid-cols-[2fr_1fr_1fr_1fr] gap-4 p-3 border-b border-white/5 items-center hover:bg-white/[0.02] transition-colors">
                <div className="text-sm font-medium text-white">{proc.name}</div>
                <div className="font-mono text-xs text-white/60">{proc.pid}</div>
                <div className="font-mono text-xs text-white/80">{proc.cpu}</div>
                <div className="font-mono text-xs text-white/80">{proc.mem}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Recent Activity Logs */}
        <div className="glass-panel p-6 lg:col-span-3">
          <h2 className="text-lg font-display font-semibold mb-6 flex items-center gap-2">
            <Activity className="w-5 h-5 text-amber-400" /> Recent Activity Logs
          </h2>
          <div className="space-y-3">
            {[
              { time: '10:42:05', event: 'Connection blocked to secure-update-paypal-verify.com', type: 'alert' },
              { time: '09:15:22', event: 'User logged in successfully', type: 'info' },
              { time: '08:00:00', event: 'Daily quick scan completed. No threats found.', type: 'success' },
              { time: '04:00:00', event: 'Full system scan completed. No threats found.', type: 'success' },
            ].map((log, i) => (
              <div key={i} className="flex gap-4 p-3 rounded-lg bg-white/[0.02] border border-white/5 items-start">
                <div className="font-mono text-xs text-white/40 mt-0.5 w-20 shrink-0">{log.time}</div>
                <div className="flex items-start gap-2">
                  {log.type === 'alert' && <ShieldAlert className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />}
                  {log.type === 'info' && <Info className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />}
                  {log.type === 'success' && <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />}
                  <span className="text-sm text-white/80">{log.event}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </motion.div>
  );
}

// --- Shared UI Components ---

function NavItem({ icon, label, active = false, onClick }: { icon: React.ReactNode, label: string, active?: boolean, onClick?: () => void }) {
  return (
    <button onClick={onClick} className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl transition-all ${
      active 
        ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' 
        : 'text-white/60 hover:bg-white/5 hover:text-white border border-transparent'
    }`}>
      {React.cloneElement(icon as React.ReactElement, { className: 'w-5 h-5' })}
      <span className="font-medium text-sm">{label}</span>
    </button>
  );
}

function StatCard({ title, value, trend, trendUp, icon, alert = false }: { title: string, value: string, trend: string, trendUp: boolean, icon: React.ReactNode, alert?: boolean }) {
  return (
    <div className={`glass-panel p-6 relative overflow-hidden group ${alert ? 'border-red-500/20' : ''}`}>
      {alert && <div className="absolute top-0 right-0 w-32 h-32 bg-red-500/10 blur-3xl -mr-10 -mt-10"></div>}
      <div className="flex justify-between items-start mb-4 relative z-10">
        <div className="p-2 bg-white/5 rounded-lg border border-white/10">
          {icon}
        </div>
        <div className={`flex items-center gap-1 text-xs font-medium px-2 py-1 rounded-full ${
          trendUp ? 'bg-emerald-500/10 text-emerald-400' : 'bg-red-500/10 text-red-400'
        }`}>
          {trendUp ? <ArrowUpRight className="w-3 h-3" /> : <ArrowDownRight className="w-3 h-3" />}
          {trend}
        </div>
      </div>
      <div className="relative z-10">
        <h3 className="text-white/50 text-sm font-medium mb-1">{title}</h3>
        <div className="text-3xl font-display font-bold font-mono tracking-tight">{value}</div>
      </div>
    </div>
  );
}
