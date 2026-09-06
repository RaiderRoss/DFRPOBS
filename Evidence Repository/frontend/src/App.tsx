import { BrowserRouter, NavLink, Route, Routes } from 'react-router-dom'
import './App.css'
import { navTabs, type PageName } from './api/api'
import RepositoryPage from './pages/RepositoryPage.tsx'

export const pageRoutes: Record<PageName, string> = {
    Overview: '/',
    'Trigger events': '/trigger-events',
    'Work groups': '/work-groups',
}

function Dashboard() {

    return (
        <main className="app-shell">
            <section className="hero-panel">
                <header className="topbar">
                    <div>
                        <p className="eyebrow">DFRaaS / evidence repository</p>
                        <h1>Investigate what the repository actually recorded.</h1>
                        <p className="lede">A focused operator console for immutable trigger events and the work groups that classify evidence.</p>
                    </div>
                    <div className="status-card"><span className="status-pill">Repository console</span><strong>LIVE</strong><span>Basic-authenticated access to the Spring API</span></div>
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
