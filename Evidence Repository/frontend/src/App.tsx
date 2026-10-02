import { ConfigProvider, Layout, Menu, Space, Tag, Typography } from 'antd'
import { BrowserRouter, Route, Routes, useLocation, useNavigate } from 'react-router-dom'
import './App.css'
import { navTabs, type PageName } from './api/api'
import RepositoryPage from './pages/RepositoryPage.tsx'


export const pageRoutes: Record<PageName, string> = {
    Overview: '/',
    'Trigger events': '/trigger-events',
    'Work groups': '/work-groups',
    'Evidence sources': '/evidence-sources',
    'Evidence items': '/evidence-items',
}

function Dashboard() {
    const location = useLocation()
    const navigate = useNavigate()
    const activeTab = navTabs.find((tab) => pageRoutes[tab] === location.pathname) ?? 'Overview'

    return (
        <Layout className="app-layout">
            <Layout.Header className="app-header">
                <div className="header-inner">
                    <Space className="brand-row" align="center" size={10}>
                        <Tag color="cyan">DFRaaS</Tag>
                        <Typography.Text className="brand-caption">Evidence operations</Typography.Text>
                    </Space>
                    <Space className="title-row" direction="vertical" size={2}>
                        <Typography.Title level={1}>Evidence repository</Typography.Title>
                    </Space>
                    <Menu
                        className="app-navigation"
                        mode="horizontal"
                        selectedKeys={[activeTab]}
                        items={navTabs.map((tab) => ({ key: tab, label: tab }))}
                        onClick={({ key }) => navigate(pageRoutes[key as PageName])}
                    />
                </div>
            </Layout.Header>
            <Layout.Content className="app-content">
                <Routes>
                    <Route path="*" element={<RepositoryPage />} />
                </Routes>
            </Layout.Content>
        </Layout>
    )
}

function App() {
    return <ConfigProvider theme={{ token: { colorPrimary: '#087f72', borderRadius: 4, fontFamily: 'Inter, Segoe UI, sans-serif' }, components: { Menu: { darkItemBg: 'transparent', darkItemSelectedBg: 'rgba(255,255,255,.12)', darkItemSelectedColor: '#fff' } } }}><BrowserRouter><Dashboard /></BrowserRouter></ConfigProvider>
}

export default App
