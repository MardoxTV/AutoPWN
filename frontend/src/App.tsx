import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Sidebar from './components/Sidebar'
import Dashboard from './pages/Dashboard'
import NewAttack from './pages/NewAttack'
import LiveView from './pages/LiveView'
import Results from './pages/Results'
import ToolsStatus from './pages/ToolsStatus'
import Settings from './pages/Settings'
import AzureAssess from './pages/AzureAssess'
import AzureResults from './pages/AzureResults'

export default function App() {
  return (
    <BrowserRouter>
      <div className="flex h-screen overflow-hidden">
        <Sidebar />
        <main className="flex-1 overflow-y-auto bg-gray-950">
          <Routes>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/attack" element={<NewAttack />} />
            <Route path="/live/:jobId" element={<LiveView />} />
            <Route path="/results/:jobId" element={<Results />} />
            <Route path="/tools" element={<ToolsStatus />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/azure" element={<AzureAssess />} />
            <Route path="/azure/results/:jobId" element={<AzureResults />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}
