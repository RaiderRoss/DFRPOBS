import { FormEvent, useEffect, useState } from 'react'
import { repositoryApi, type TriggerEvent } from '../api/api'

function formatDate(value: string) {
    return new Intl.DateTimeFormat('en-ZA', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value))
}

export default function TriggerEventsPage() {
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
        <aside className="panel detail-panel"><p className="panel-label">GET /by-external-id</p><h2>Resolve a source event</h2><p className="panel-copy">External identifiers are unique only within their source system.</p><form className="lookup-form source-lookup-form" onSubmit={resolve}><input required placeholder="Source system" value={lookup.sourceSystem} onChange={(event) => setLookup({ ...lookup, sourceSystem: event.target.value })} /><input required placeholder="External event ID" value={lookup.externalEventId} onChange={(event) => setLookup({ ...lookup, externalEventId: event.target.value })} /><button className="action primary" type="submit">Resolve event</button></form>{selected && <div className="detail-block"><span className="detail-kicker">Selected record</span><strong>{selected.triggerType}</strong><dl><dt>Repository ID</dt><dd>{selected.id}</dd><dt>Fired</dt><dd>{formatDate(selected.firedAt)}</dd><dt>Received</dt><dd>{formatDate(selected.receivedAt)}</dd><dt>SHA-256</dt><dd><code>{selected.payloadSha256}</code></dd></dl></div>}</aside>
    </section>
}
