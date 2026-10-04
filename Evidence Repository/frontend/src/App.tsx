import { BrowserRouter, NavLink, Route, Routes } from 'react-router-dom'
import './App.css'
import { navTabs, type PageName } from './api/api'
import RepositoryPage from './pages/RepositoryPage.tsx'

export const pageRoutes: Record<PageName, string> = {
    Overview: '/',
    Incidents: '/incidents',
    'Trigger events': '/trigger-events',
    'Work groups': '/work-groups',
    'Evidence sources': '/evidence-sources',
    'Evidence items': '/evidence-items',
}

function Dashboard() {

    return (
        <main className="app-shell">
            <section className="hero-panel">
                <header className="topbar">
                    <div>
                        <h1>DFRaaS / evidence repository</h1>
                        <p className="lede">Online platform for ease of management of the evidence repository.</p>
                    </div>
                </header>
                <nav className="tab-bar" aria-label="Dashboard sections">
                    {navTabs.map((tab) => <NavLink key={tab} to={pageRoutes[tab]} className={({ isActive }) => isActive ? 'tab active' : 'tab'}>{tab}</NavLink>)}
                </nav>
                <Routes>
                    <Route path="*" element={<RepositoryPage />} />
                </Routes>
            </section>
        </main>
    )
}

function App() {
    return <BrowserRouter><Dashboard /></BrowserRouter>
}

export default App
