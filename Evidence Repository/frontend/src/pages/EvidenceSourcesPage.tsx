import { FormEvent, useEffect, useState } from 'react'
import { repositoryApi, type EvidenceSource } from '../api/api'

function formatDate(value: string | null) {
    return value ? new Intl.DateTimeFormat('en-ZA', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value)) : 'No evidence yet'
}

export default function EvidenceSourcesPage() {
    const [sources, setSources] = useState<EvidenceSource[]>([])
    const [sourceKey, setSourceKey] = useState('')
    const [form, setForm] = useState({ sourceKey: '', displayName: '', workGroupId: '', sourceType: '', expectedIntervalSeconds: '' })
    const [message, setMessage] = useState('')
    const [error, setError] = useState('')

    async function load() {
        try { setSources(await repositoryApi.listEvidenceSources(sourceKey)); setError('') }
        catch (exception) { setError(exception instanceof Error ? exception.message : 'Unable to load evidence sources.') }
    }

    useEffect(() => { void load() }, [sourceKey])

    async function register(event: FormEvent) {
        event.preventDefault()
        try {
            await repositoryApi.createEvidenceSource({
                sourceKey: form.sourceKey,
                displayName: form.displayName,
                workGroupId: form.workGroupId,
                sourceType: form.sourceType,
                expectedIntervalSeconds: form.expectedIntervalSeconds ? Number(form.expectedIntervalSeconds) : null,
            })
            setForm({ sourceKey: '', displayName: '', workGroupId: '', sourceType: '', expectedIntervalSeconds: '' })
            setMessage('Evidence source registered.')
            void load()
        } catch (exception) { setMessage(exception instanceof Error ? exception.message : 'Evidence source could not be registered.') }
    }

    return <section className="workspace-grid source-grid">
        <article className="panel wide-panel">
            <div className="panel-header"><div><p className="panel-label">GET /api/evidence-sources</p><h2>Registered evidence sources</h2></div><span className="chip">{sources.length} loaded</span></div>
            <div className="toolbar"><input aria-label="Find evidence source" placeholder="Filter by source key" value={sourceKey} onChange={(event) => setSourceKey(event.target.value)} /><button className="action" type="button" onClick={() => void load()}>Refresh</button></div>
            {error && <p className="error-message">{error}</p>}
            <div className="source-list">{sources.map((source) => <article className="source-row" key={source.id}><div><strong>{source.displayName}</strong><span>{source.sourceKey} / {source.sourceType}</span></div><div><span className={`status-text ${source.status.toLowerCase()}`}>{source.status}</span><small>Last evidence: {formatDate(source.lastEvidenceAt)}</small></div></article>)}{sources.length === 0 && <p className="empty-state">No evidence sources match this filter.</p>}</div>
        </article>
        <aside className="panel detail-panel"><p className="panel-label">POST /api/evidence-sources</p><h2>Register a source</h2><p className="panel-copy">Registration assigns the classification inherited by every artifact from this collector.</p><form className="resource-form" onSubmit={register}><input required pattern="[a-z0-9]+([._-][a-z0-9]+)*" placeholder="source-key" value={form.sourceKey} onChange={(event) => setForm({ ...form, sourceKey: event.target.value })} /><input required placeholder="Human-readable name" value={form.displayName} onChange={(event) => setForm({ ...form, displayName: event.target.value })} /><input required placeholder="Work group ID" value={form.workGroupId} onChange={(event) => setForm({ ...form, workGroupId: event.target.value })} /><input required pattern="[A-Z0-9]+(_[A-Z0-9]+)*" placeholder="SOURCE_TYPE" value={form.sourceType} onChange={(event) => setForm({ ...form, sourceType: event.target.value })} /><input type="number" min="1" placeholder="Expected interval (seconds)" value={form.expectedIntervalSeconds} onChange={(event) => setForm({ ...form, expectedIntervalSeconds: event.target.value })} /><button className="action primary" type="submit">Register source</button></form>{message && <p className="form-message">{message}</p>}</aside>
    </section>
}
