import { useState } from 'react'
import { Route, Routes } from 'react-router-dom'
import { hasCredentials } from '../api/api'
import AuthPanel from './AuthPanel'
import EvidenceItemsPage from './EvidenceItemsPage'
import EvidenceSourcesPage from './EvidenceSourcesPage'
import IncidentsPage from './IncidentsPage'
import OverviewPage from './OverviewPage'
import TriggerEventsPage from './TriggerEventsPage'
import WorkGroupsPage from './WorkGroupsPage'

export default function RepositoryPage() {
    const [connected, setConnected] = useState(hasCredentials())
    if (!connected) return <AuthPanel onAuthenticated={() => setConnected(true)} />

    return <Routes>
        <Route path="/" element={<OverviewPage />} />
        <Route path="/incidents" element={<IncidentsPage />} />
        <Route path="/trigger-events" element={<TriggerEventsPage />} />
        <Route path="/work-groups" element={<WorkGroupsPage />} />
        <Route path="/evidence-sources" element={<EvidenceSourcesPage />} />
        <Route path="/evidence-items" element={<EvidenceItemsPage />} />
        <Route path="*" element={<OverviewPage />} />
    </Routes>
}
