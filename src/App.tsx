import AdminDashboard from './components/AdminDashboard';

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

export default function App() {
  return <AdminDashboard />;
}
