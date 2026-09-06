import { FormEvent, useEffect, useState } from 'react'
import { hasCredentials, repositoryApi, setCredentials, clearCredentials, type TriggerEvent, type WorkGroup } from '../api/api'

function formatDate(value: string) {
    return new Intl.DateTimeFormat('en-ZA', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value))
}

function AuthPanel({ onAuthenticated }: { onAuthenticated: () => void }) {
    const [username, setUsername] = useState('admin')
    const [password, setPassword] = useState('admin')
    const [error, setError] = useState('')

    async function submit(event: FormEvent) {
        event.preventDefault()
        setCredentials(username, password)
        try {
            await repositoryApi.listWorkGroups()
            onAuthenticated()
        } catch {
            clearCredentials()
            setError('Credentials were rejected by the repository.')
        }
    }

    return <section className="panel auth-panel">
        <p className="panel-label">Connection required</p>
        <h2>Sign in to the repository</h2>
        <p className="panel-copy">The API uses HTTP Basic authentication in local development.</p>
        <form className="auth-form" onSubmit={submit}>
            <label>Username<input value={username} onChange={(event) => setUsername(event.target.value)} /></label>
            <label>Password<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} /></label>
            <button className="action primary" type="submit">Connect</button>
        </form>
        {error && <p className="error-message">{error}</p>}
    </section>
}

function TriggerEvents() {
    const [events, setEvents] = useState<TriggerEvent[]>([])
    const [source, setSource] = useState('')
    const [lookup, setLookup] = useState({ sourceSystem: '', externalEventId: '' })
    const [selected, setSelected] = useState<TriggerEvent | null>(null)
    const [error, setError] = useState('')

    async function load() {
        try { setEvents((await repositoryApi.listTriggerEvents(source)).content); setError('') }
        catch (exception) { setError(exception instanceof Error ? exception.message : 'Unable to load trigger events.') }
    }

    useEffect(() => { void load() }, [source])

    async function resolve(event: FormEvent) {
        event.preventDefault()
        try { setSelected(await repositoryApi.getTriggerEventByExternalId(lookup.sourceSystem, lookup.externalEventId)); setError('') }
        catch (exception) { setError(exception instanceof Error ? exception.message : 'Event was not found.') }
    }

    return <section className="workspace-grid">
        <article className="panel wide-panel">
            <div className="panel-header"><div><p className="panel-label">GET /api/trigger-events</p><h2>Recorded trigger events</h2></div><span className="chip secure">Read only</span></div>
            <div className="toolbar"><input aria-label="Filter by source system" placeholder="Filter source system" value={source} onChange={(event) => setSource(event.target.value)} /><button className="action" type="button" onClick={() => void load()}>Refresh</button></div>
            {error && <p className="error-message">{error}</p>}
            <div className="event-table-wrap"><table><thead><tr><th>Trigger</th><th>Source</th><th>Received</th><th>Digest</th><th /></tr></thead><tbody>{events.map((item) => <tr key={item.id}><td><strong>{item.triggerType}</strong><small>{item.externalEventId}</small></td><td>{item.sourceSystem}</td><td>{formatDate(item.receivedAt)}</td><td><code>{item.payloadSha256.slice(0, 12)}...</code></td><td><button className="text-button" type="button" onClick={() => { void repositoryApi.getTriggerEvent(item.id).then(setSelected) }}>Inspect</button></td></tr>)}</tbody></table>{events.length === 0 && <p className="empty-state">No trigger events match this filter.</p>}</div>
        </article>
        <aside className="panel detail-panel">
            <p className="panel-label">GET /by-external-id</p><h2>Resolve a source event</h2><p className="panel-copy">External identifiers are unique only within their source system.</p>
            <form className="lookup-form" onSubmit={resolve}><input required placeholder="Source system" value={lookup.sourceSystem} onChange={(event) => setLookup({ ...lookup, sourceSystem: event.target.value })} /><input required placeholder="External event ID" value={lookup.externalEventId} onChange={(event) => setLookup({ ...lookup, externalEventId: event.target.value })} /><button className="action primary" type="submit">Resolve event</button></form>
            {selected && <div className="detail-block"><span className="detail-kicker">Selected record</span><strong>{selected.triggerType}</strong><dl><dt>Repository ID</dt><dd>{selected.id}</dd><dt>Fired</dt><dd>{formatDate(selected.firedAt)}</dd><dt>Received</dt><dd>{formatDate(selected.receivedAt)}</dd><dt>SHA-256</dt><dd><code>{selected.payloadSha256}</code></dd></dl></div>}
        </aside>
    </section>
}

function WorkGroups() {
    const [groups, setGroups] = useState<WorkGroup[]>([])
    const [form, setForm] = useState({ name: '', classificationCode: '' })
    const [filter, setFilter] = useState('')
    const [message, setMessage] = useState('')

    async function load() { setGroups(await repositoryApi.listWorkGroups(filter)) }
    useEffect(() => { void load() }, [filter])

    async function create(event: FormEvent) {
        event.preventDefault()
        try { await repositoryApi.createWorkGroup(form.name, form.classificationCode); setForm({ name: '', classificationCode: '' }); setMessage('Work group created.'); void load() }
        catch (exception) { setMessage(exception instanceof Error ? exception.message : 'Work group could not be created.') }
    }

    return <section className="workspace-grid">
        <article className="panel wide-panel"><div className="panel-header"><div><p className="panel-label">GET /api/work-groups</p><h2>Classification catalogue</h2></div><span className="chip">{groups.length} loaded</span></div><div className="toolbar"><input aria-label="Filter by classification code" placeholder="Filter classification code" value={filter} onChange={(event) => setFilter(event.target.value)} /><button className="action" type="button" onClick={() => void load()}>Refresh</button></div><div className="group-list">{groups.map((group) => <article className="group-row" key={group.id}><div><strong>{group.name}</strong><span>{group.classificationCode}</span></div><small>Created {formatDate(group.createdAt)}</small><button className="text-button" type="button" onClick={() => void repositoryApi.getWorkGroup(group.id).then((item) => setMessage(`${item.name} / ${item.classificationCode}`))}>Inspect</button></article>)}</div></article>
        <aside className="panel detail-panel"><p className="panel-label">POST /api/work-groups</p><h2>Create a classification</h2><p className="panel-copy">The server assigns the ID and creation timestamp. Codes use SCREAMING_SNAKE_CASE.</p><form className="lookup-form" onSubmit={create}><input required placeholder="Human-readable name" value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} /><input required pattern="[A-Z0-9]+(_[A-Z0-9]+)*" placeholder="CLASSIFICATION_CODE" value={form.classificationCode} onChange={(event) => setForm({ ...form, classificationCode: event.target.value })} /><button className="action primary" type="submit">Create work group</button></form>{message && <p className="form-message">{message}</p>}</aside>
    </section>
}

export default function RepositoryPage() {
    const [connected, setConnected] = useState(hasCredentials())
    const path = window.location.pathname
    if (!connected) return <AuthPanel onAuthenticated={() => setConnected(true)} />
    return <>{path === '/work-groups' ? <WorkGroups /> : path === '/trigger-events' ? <TriggerEvents /> : <Overview connected onDisconnect={() => { clearCredentials(); setConnected(false) }} />}</>
}

function Overview({ onDisconnect }: { connected: boolean; onDisconnect: () => void }) {
    const [events, setEvents] = useState<TriggerEvent[]>([])
    const [groups, setGroups] = useState<WorkGroup[]>([])
    useEffect(() => { void Promise.all([repositoryApi.listTriggerEvents(), repositoryApi.listWorkGroups()]).then(([eventPage, workGroups]) => { setEvents(eventPage.content); setGroups(workGroups) }) }, [])
    return <section className="overview-grid"><article className="panel spotlight"><div className="panel-header"><div><p className="panel-label">Repository overview</p><h2>Evidence intake at a glance</h2></div><button className="text-button" type="button" onClick={onDisconnect}>Disconnect</button></div><p className="panel-copy">A live summary of the append-only records currently available to investigators.</p><div className="metric-row"><div><span className="metric-value">{events.length}</span><span className="metric-label">recent trigger events</span></div><div><span className="metric-value">{new Set(events.map((event) => event.sourceSystem)).size}</span><span className="metric-label">source systems</span></div><div><span className="metric-value">{groups.length}</span><span className="metric-label">work groups</span></div></div></article><article className="panel"><p className="panel-label">API surface</p><h2>Available operations</h2><ul className="endpoint-list"><li><code>GET</code> trigger events, filtered and paginated</li><li><code>GET</code> event by repository or external ID</li><li><code>GET</code> work groups, optionally by code</li><li><code>POST</code> a new work group</li></ul></article></section>
}